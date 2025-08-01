use std::fmt::Debug;
use std::sync::Arc;

use ampd_proto::broadcast_service_server::BroadcastService;
use ampd_proto::{AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse};
use async_trait::async_trait;
use axelar_wasm_std::FnExt;
use futures::TryFutureExt;
use tonic::{Request, Response, Status};
use tracing::instrument;

use crate::broadcast;
use crate::grpc::reqs::Validate;
use crate::grpc::status;

#[derive(Clone, Debug)]
pub struct Service<C>
where
    C: crate::cosmos::CosmosClient,
{
    msg_queue_client: broadcast::MsgQueueClient<C>,
}

impl<C> Service<C>
where
    C: crate::cosmos::CosmosClient,
{
    pub fn new(msg_queue_client: broadcast::MsgQueueClient<C>) -> Self {
        Self { msg_queue_client }
    }
}

#[async_trait]
impl<C> BroadcastService for Service<C>
where
    C: crate::cosmos::CosmosClient + Clone + Send + Sync + 'static + Debug,
{
    #[instrument]
    async fn broadcast(
        &self,
        req: Request<BroadcastRequest>,
    ) -> Result<Response<BroadcastResponse>, Status> {
        let msg = req
            .validate()
            .inspect_err(status::log("invalid broadcast request"))
            .map_err(status::StatusExt::into_status)?;

        self.msg_queue_client
            .clone()
            .enqueue(msg)
            .map_err(Arc::new)
            .and_then(|rx| rx)
            .await
            .map(|(tx_hash, index)| BroadcastResponse { tx_hash, index })
            .map(Response::new)
            .inspect_err(|err| err.as_ref().then(status::log("message broadcast error")))
            .map_err(|err| status::StatusExt::into_status(err.as_ref()))
    }

    async fn address(
        &self,
        _req: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        Ok(Response::new(AddressResponse {
            address: self.msg_queue_client.address().to_string(),
        }))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::time::Duration;

    use ampd_proto::broadcast_service_server::BroadcastService;
    use ampd_proto::{AddressRequest, BroadcastRequest};
    use axelar_wasm_std::nonempty;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmos_sdk_proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateResponse;
    use cosmrs::{Any, Gas};
    use futures::future::join_all;
    use futures::Stream;
    use mockall::{predicate, Sequence};
    use report::ErrorExt;
    use tokio_stream::StreamExt;
    use tonic::{Code, Request, Status};

    use crate::broadcast::DecCoin;
    use crate::cosmos::MockCosmosClient;
    use crate::grpc::broadcast_service::Service;
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::{broadcast, PREFIX};

    const GAS_CAP: Gas = 10000;

    async fn setup(
        mut broadcaster_mock_cosmos_client: MockCosmosClient,
    ) -> (
        Service<MockCosmosClient>,
        impl Stream<Item = nonempty::Vec<broadcast::QueueMsg>>,
    ) {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };

        let mut seq = Sequence::new();
        broadcaster_mock_cosmos_client
            .expect_account()
            .once()
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });

        broadcaster_mock_cosmos_client
            .expect_balance()
            .once()
            .with(predicate::eq(QueryBalanceRequest {
                address: address.to_string(),
                denom: gas_price_denom.to_string(),
            }))
            .in_sequence(&mut seq)
            .return_once(move |_| {
                Ok(QueryBalanceResponse {
                    balance: Some(Coin {
                        denom: gas_price_denom.to_string(),
                        amount: "1000000".to_string(),
                    }),
                })
            });

        let broadcaster = broadcast::Broadcaster::builder()
            .client(broadcaster_mock_cosmos_client)
            .chain_id("chain_id".try_into().unwrap())
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();
        let (msg_queue, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            100,
            GAS_CAP,
            Duration::from_secs(1),
        );

        (Service::new(msg_queue_client), msg_queue)
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_req_is_invalid() {
        let (service, _) = setup(MockCosmosClient::new()).await;
        let res = service.broadcast(broadcast_req(None)).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_enqueue_failed() {
        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(|| {
            let mut mock_cosmos_client = MockCosmosClient::new();
            mock_cosmos_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("simulate error").into_report()));

            mock_cosmos_client
        });

        let (service, _) = setup(mock_cosmos_client).await;
        let res = service.broadcast(broadcast_req(Some(dummy_msg()))).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_broadcast_failed() {
        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(|| {
            let mut mock_cosmos_client = MockCosmosClient::new();
            mock_cosmos_client.expect_simulate().return_once(|_| {
                Ok(SimulateResponse {
                    gas_info: Some(GasInfo {
                        gas_wanted: GAS_CAP + 1,
                        gas_used: GAS_CAP + 1,
                    }),
                    result: None,
                })
            });

            mock_cosmos_client
        });

        let (service, mut msg_queue) = setup(mock_cosmos_client).await;
        tokio::spawn(async move { while msg_queue.next().await.is_some() {} });
        let res = service.broadcast(broadcast_req(Some(dummy_msg()))).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn broadcast_should_return_tx_hash_and_index() {
        let tx_hash = "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b";
        let msg_count = 10;
        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client
            .expect_clone()
            .times(msg_count)
            .returning(move || {
                let mut mock_cosmos_client = MockCosmosClient::new();
                mock_cosmos_client.expect_simulate().return_once(move |_| {
                    Ok(SimulateResponse {
                        gas_info: Some(GasInfo {
                            gas_wanted: GAS_CAP / msg_count as u64,
                            gas_used: GAS_CAP / msg_count as u64,
                        }),
                        result: None,
                    })
                });

                mock_cosmos_client
            });

        let (service, mut msg_queue) = setup(mock_cosmos_client).await;
        let service = Arc::new(service);
        let handles = join_all(
            (0..msg_count)
                .map(|_| {
                    let service = service.clone();

                    tokio::spawn(async move {
                        let res = service
                            .broadcast(broadcast_req(Some(dummy_msg())))
                            .await
                            .unwrap()
                            .into_inner();

                        (res.tx_hash, res.index)
                    })
                })
                .collect::<Vec<_>>(),
        );

        let msgs: Vec<_> = msg_queue.next().await.unwrap().into();
        assert_eq!(msgs.len(), msg_count);
        for (i, msg) in msgs.into_iter().enumerate() {
            assert_eq!(msg.gas, GAS_CAP / msg_count as u64);
            msg.tx_res_callback
                .send(Ok((tx_hash.to_string(), i as u64)))
                .unwrap();
        }

        let mut results = handles.await;
        results.sort_by(|result_a, result_b| {
            let result_a = result_a.as_ref().unwrap();
            let result_b = result_b.as_ref().unwrap();

            result_a.1.cmp(&result_b.1)
        });
        for (i, result) in results.into_iter().enumerate() {
            let (tx_hash, index) = result.unwrap();
            assert_eq!(tx_hash, tx_hash.to_string());
            assert_eq!(index, i as u64);
        }
    }

    #[tokio::test]
    async fn address_should_return_msg_queue_client_address() {
        let pub_key = random_cosmos_public_key();
        let expected_address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let base_account = BaseAccount {
            address: expected_address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };
        let gas_adjustment = 1.5;
        let gas_price_amount = 0.025;
        let gas_price_denom = "uaxl";

        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_account().return_once(move |_| {
            Ok(QueryAccountResponse {
                account: Some(Any::from_msg(&base_account).unwrap()),
            })
        });
        mock_cosmos_client.expect_balance().return_once(move |_| {
            Ok(QueryBalanceResponse {
                balance: Some(Coin {
                    denom: "uaxl".to_string(),
                    amount: "1000000".to_string(),
                }),
            })
        });
        let broadcaster = broadcast::Broadcaster::builder()
            .client(mock_cosmos_client)
            .chain_id("chain-id".parse().unwrap())
            .pub_key(pub_key)
            .gas_adjustment(gas_adjustment)
            .gas_price(DecCoin::new(gas_price_amount, gas_price_denom).unwrap())
            .build()
            .await
            .unwrap();

        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            1000u64,
            Duration::from_secs(1),
        );

        let service = Service::new(msg_queue_client);

        let req = Request::new(AddressRequest {});
        let res = service.address(req).await.unwrap().into_inner();

        assert_eq!(res.address, expected_address.to_string());
    }

    fn broadcast_req(msg: Option<Any>) -> Request<BroadcastRequest> {
        Request::new(BroadcastRequest { msg })
    }

    fn dummy_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3, 4],
        }
    }
}
