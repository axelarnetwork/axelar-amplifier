use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractStateRequest,
    ContractStateResponse, ContractsRequest, ContractsResponse, SubscribeRequest,
    SubscribeResponse,
};
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::FnExt;
use futures::{Stream, TryFutureExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::instrument;
use typed_builder::TypedBuilder;

use crate::grpc::reqs::Validate;
use crate::grpc::status;
use crate::types::TMAddress;
use crate::{broadcast, cosmos, event_sub};

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Chain specific configurations
    // TODO: remove this once we use the coordinator contract to query for contract addresses
    pub chains: Vec<ChainConfig>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ChainConfig {
    pub chain_name: ChainName,
    pub voting_verifier: TMAddress,
    pub multisig_prover: TMAddress,
    pub multisig: TMAddress,
}

#[derive(Debug, TypedBuilder)]
pub struct Service<E, C>
where
    E: event_sub::EventSub,
    C: cosmos::CosmosClient,
{
    event_sub: E,
    msg_queue_client: broadcast::MsgQueueClient<C>,
    cosmos_client: C,
    service_registry: TMAddress,
    rewards: TMAddress,
    config: Config,
}

#[async_trait]
impl<E, C> BlockchainService for Service<E, C>
where
    E: event_sub::EventSub + Send + Sync + 'static + Debug,
    C: cosmos::CosmosClient + Clone + Send + Sync + 'static + Debug,
{
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, Status>> + Send>>;

    #[instrument]
    async fn subscribe(
        &self,
        req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let filters = req
            .validate()
            .inspect_err(status::log("invalid subscribe request"))
            .map_err(status::StatusExt::into_status)?;

        Ok(Response::new(Box::pin(
            self.event_sub
                .subscribe()
                .filter(move |event| match event {
                    Ok(event) => filters.filter(event),
                    Err(_) => true,
                })
                .map_ok(Into::into)
                .map_ok(|event| SubscribeResponse { event: Some(event) })
                .inspect_err(status::log("event subscription error"))
                .map_err(status::StatusExt::into_status),
        )))
    }

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

    #[instrument]
    async fn contract_state(
        &self,
        req: Request<ContractStateRequest>,
    ) -> Result<Response<ContractStateResponse>, Status> {
        let (contract, query) = req
            .validate()
            .inspect_err(status::log("invalid contract state request"))
            .map_err(status::StatusExt::into_status)?;

        cosmos::contract_state(&mut self.cosmos_client.clone(), &contract, query)
            .await
            .map(|result| ContractStateResponse { result })
            .map(Response::new)
            .inspect_err(status::log("query contract state error"))
            .map_err(status::StatusExt::into_status)
    }

    async fn address(
        &self,
        _req: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        Ok(Response::new(AddressResponse {
            address: self.msg_queue_client.address().to_string(),
        }))
    }

    #[instrument]
    async fn contracts(
        &self,
        req: Request<ContractsRequest>,
    ) -> Result<Response<ContractsResponse>, Status> {
        let chain = req
            .validate()
            .inspect_err(status::log("invalid contracts request"))
            .map_err(status::StatusExt::into_status)?;

        // TODO: use coordinator contract to query for contract addresses instead of using configurations
        let chain_config = self
            .config
            .chains
            .iter()
            .find(|c| c.chain_name == chain)
            .ok_or_else(|| Status::not_found("chain contracts not found"))?;

        Ok(Response::new(ContractsResponse {
            voting_verifier: chain_config.voting_verifier.to_string(),
            multisig_prover: chain_config.multisig_prover.to_string(),
            service_registry: self.service_registry.to_string(),
            rewards: self.rewards.to_string(),
            multisig: chain_config.multisig.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axelar_wasm_std::{chain_name, nonempty};
    use cosmos_sdk_proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
    use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
    use cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo;
    use cosmrs::proto::cosmos::tx::v1beta1::SimulateResponse;
    use cosmrs::proto::cosmwasm::wasm::v1::{
        QuerySmartContractStateRequest, QuerySmartContractStateResponse,
    };
    use cosmrs::{Any, Gas};
    use error_stack::report;
    use events::{self, Event};
    use futures::future::join_all;
    use futures::{stream, StreamExt};
    use mockall::{predicate, Sequence};
    use report::ErrorExt;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::{Code, Request};

    use super::*;
    use crate::broadcast::DecCoin;
    use crate::cosmos::MockCosmosClient;
    use crate::event_sub::{self, MockEventSub};
    use crate::types::{random_cosmos_public_key, TMAddress};
    use crate::PREFIX;

    const GAS_CAP: Gas = 10000;

    async fn setup(
        mock_event_sub: MockEventSub,
        mut broadcaster_mock_cosmos_client: MockCosmosClient,
        mock_cosmos_client: MockCosmosClient,
    ) -> (
        Service<MockEventSub, MockCosmosClient>,
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
        let service = Service::builder()
            .event_sub(mock_event_sub)
            .msg_queue_client(msg_queue_client)
            .cosmos_client(mock_cosmos_client)
            .service_registry(TMAddress::random(PREFIX))
            .rewards(TMAddress::random(PREFIX))
            .config(Config {
                chains: vec![ChainConfig {
                    chain_name: chain_name!("test-chain"),
                    voting_verifier: TMAddress::random(PREFIX),
                    multisig_prover: TMAddress::random(PREFIX),
                    multisig: TMAddress::random(PREFIX),
                }],
            })
            .build();

        (service, msg_queue)
    }

    #[tokio::test]
    async fn subscribe_should_stream_events_successfully() {
        let expected = vec![
            block_begin_event(100),
            abci_event("test_event", vec![("key1", "value1")], None),
            block_end_event(100),
        ];

        let mut mock_event_sub = MockEventSub::new();
        let events = expected.clone();
        mock_event_sub
            .expect_subscribe()
            .return_once(move || stream::iter(events.into_iter().map(Result::Ok)).boxed());

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(vec![], true))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        for expected in expected {
            let actual = event_stream.next().await.unwrap().unwrap();
            assert_eq!(actual.event, Some(expected.into()))
        }
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_any_filter_is_invalid() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter::default()],
                true,
            ))
            .await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));

        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter {
                    contract: "invalid_contract".to_string(),
                    ..Default::default()
                }],
                true,
            ))
            .await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn subscribe_should_handle_latest_block_query_error() {
        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub.expect_subscribe().return_once(|| {
            tokio_stream::once(Err(report!(event_sub::Error::LatestBlockQuery))).boxed()
        });

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter {
                    r#type: "event_type".to_string(),
                    ..Default::default()
                }],
                true,
            ))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let error = event_stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_handle_block_results_query_error() {
        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub.expect_subscribe().return_once(move || {
            tokio_stream::once(Err(report!(event_sub::Error::BlockResultsQuery {
                block: 100u32.into()
            })))
            .boxed()
        });

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter {
                    r#type: "event_type".to_string(),
                    ..Default::default()
                }],
                true,
            ))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let error = event_stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_handle_event_decoding_error() {
        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub.expect_subscribe().return_once(move || {
            tokio_stream::once(Err(report!(event_sub::Error::EventDecoding {
                block: 100u32.into()
            })))
            .boxed()
        });

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter {
                    r#type: "event_type".to_string(),
                    ..Default::default()
                }],
                true,
            ))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let error = event_stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::Internal);
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_handle_broadcast_stream_recv_error() {
        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub.expect_subscribe().return_once(move || {
            tokio_stream::once(Err(BroadcastStreamRecvError::Lagged(10).into_report())).boxed()
        });

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(
                vec![ampd_proto::EventFilter {
                    r#type: "event_type".to_string(),
                    ..Default::default()
                }],
                true,
            ))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let error = event_stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::DataLoss);
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_filter_events_by_event_type() {
        let expected = abci_event("event_type_2", vec![("key2", "\"value2\"")], None);
        let events = vec![
            abci_event("event_type_1", vec![("key1", "\"value1\"")], None),
            expected.clone(),
            abci_event("event_type_3", vec![("key3", "\"value3\"")], None),
        ];

        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub
            .expect_subscribe()
            .return_once(move || stream::iter(events.into_iter().map(Result::Ok)).boxed());

        let filter = ampd_proto::EventFilter {
            r#type: "event_type_2".to_string(),
            ..Default::default()
        };
        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(vec![filter], false))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let actual = event_stream.next().await.unwrap().unwrap();
        assert_eq!(actual.event, Some(expected.into()));
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_filter_events_by_contract() {
        let expected = abci_event(
            "test_event",
            vec![],
            Some(TMAddress::random(PREFIX).to_string().as_str()),
        );
        let events = vec![
            abci_event("test_event", vec![], None),
            expected.clone(),
            abci_event(
                "test_event",
                vec![],
                Some(TMAddress::random(PREFIX).to_string().as_str()),
            ),
        ];

        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub
            .expect_subscribe()
            .return_once(move || stream::iter(events.into_iter().map(Result::Ok)).boxed());

        let filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: expected.contract_address().unwrap().to_string(),
        };
        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(vec![filter], false))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let actual = event_stream.next().await.unwrap().unwrap();
        assert_eq!(actual.event, Some(expected.into()));
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_handle_block_events_filter() {
        let expected = abci_event("test_event", vec![("key1", "\"value1\"")], None);
        let events = vec![
            block_begin_event(100),
            expected.clone(),
            block_end_event(100),
        ];

        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub
            .expect_subscribe()
            .return_once(move || stream::iter(events.into_iter().map(Result::Ok)).boxed());

        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(vec![], false))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        let actual = event_stream.next().await.unwrap().unwrap();
        assert_eq!(actual.event, Some(expected.into()));
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn subscribe_should_filter_events_by_multiple_filters() {
        let expected = vec![
            abci_event(
                "event_1",
                vec![],
                Some(TMAddress::random(PREFIX).to_string().as_str()),
            ),
            abci_event(
                "event_2",
                vec![],
                Some(TMAddress::random(PREFIX).to_string().as_str()),
            ),
        ];
        let events = vec![
            abci_event("test_event", vec![], None),
            expected[0].clone(),
            abci_event(
                "test_event",
                vec![],
                Some(TMAddress::random(PREFIX).to_string().as_str()),
            ),
            expected[1].clone(),
        ];

        let mut mock_event_sub = MockEventSub::new();
        mock_event_sub
            .expect_subscribe()
            .return_once(move || stream::iter(events.into_iter().map(Result::Ok)).boxed());

        let filter_1 = ampd_proto::EventFilter {
            r#type: "event_1".to_string(),
            ..Default::default()
        };
        let filter_2 = ampd_proto::EventFilter {
            contract: expected[1].contract_address().unwrap().to_string(),
            ..Default::default()
        };
        let (service, _) = setup(
            mock_event_sub,
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service
            .subscribe(subscribe_req(vec![filter_1, filter_2], false))
            .await
            .unwrap();
        let mut event_stream = res.into_inner();

        for expected in expected {
            let actual = event_stream.next().await.unwrap().unwrap();
            assert_eq!(actual.event, Some(expected.into()))
        }
        assert!(event_stream.next().await.is_none());
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_req_is_invalid() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let res = service.broadcast(broadcast_req(None)).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_enqueue_failed() {
        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(|| {
            let address = TMAddress::random(PREFIX);
            let base_account = BaseAccount {
                address: address.to_string(),
                pub_key: None,
                account_number: 42,
                sequence: 10,
            };

            let mut mock_cosmos_client = MockCosmosClient::new();
            mock_cosmos_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
            mock_cosmos_client
                .expect_simulate()
                .return_once(|_| Err(Status::internal("simulate error").into_report()));

            mock_cosmos_client
        });

        let (service, _) = setup(
            MockEventSub::new(),
            mock_cosmos_client,
            MockCosmosClient::new(),
        )
        .await;
        let res = service.broadcast(broadcast_req(Some(dummy_msg()))).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_broadcast_failed() {
        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(move || {
            let address = TMAddress::random(PREFIX);
            let base_account = BaseAccount {
                address: address.to_string(),
                pub_key: None,
                account_number: 42,
                sequence: 10,
            };

            let mut mock_cosmos_client = MockCosmosClient::new();
            mock_cosmos_client.expect_account().return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any::from_msg(&base_account).unwrap()),
                })
            });
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

        let (service, mut msg_queue) = setup(
            MockEventSub::new(),
            mock_cosmos_client,
            MockCosmosClient::new(),
        )
        .await;
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
                let pub_key = random_cosmos_public_key();
                let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
                let base_account = BaseAccount {
                    address: address.to_string(),
                    pub_key: None,
                    account_number: 42,
                    sequence: 10,
                };

                let mut mock_cosmos_client = MockCosmosClient::new();
                mock_cosmos_client.expect_account().return_once(move |_| {
                    Ok(QueryAccountResponse {
                        account: Some(Any::from_msg(&base_account).unwrap()),
                    })
                });
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

        let (service, mut msg_queue) = setup(
            MockEventSub::new(),
            mock_cosmos_client,
            MockCosmosClient::new(),
        )
        .await;
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
    async fn contract_state_should_return_error_if_req_is_invalid() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let req = Request::new(ContractStateRequest {
            contract: "invalid_address".to_string(),
            query: serde_json::to_vec(&serde_json::json!({"get_config": {}})).unwrap(),
        });
        let res = service.contract_state(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_empty_query() {
        let address = TMAddress::random(PREFIX);
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: vec![],
        });
        let res = service.contract_state(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_invalid_json() {
        let address = TMAddress::random(PREFIX);
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: vec![1, 2, 3], // invalid json
        });
        let res = service.contract_state(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_cosmos_query_fails() {
        let address = TMAddress::random(PREFIX);
        let address_str = address.to_string();
        let query_bytes = serde_json::to_vec(&serde_json::json!({"get_config": {}})).unwrap();

        let mock_address = address_str.clone();
        let mock_query = query_bytes.clone();

        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(move || {
            let mut mock = MockCosmosClient::new();
            mock.expect_smart_contract_state()
                .with(predicate::eq(QuerySmartContractStateRequest {
                    address: mock_address,
                    query_data: mock_query,
                }))
                .return_once(|_| {
                    Err(report!(cosmos::Error::QueryContractState(
                        "execution error".to_string()
                    )))
                });

            mock
        });

        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            mock_cosmos_client,
        )
        .await;
        let req = Request::new(ContractStateRequest {
            contract: address_str,
            query: query_bytes,
        });
        let res = service.contract_state(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::Unknown));
    }

    #[tokio::test]
    async fn contract_state_should_return_result_successfully() {
        let address = TMAddress::random(PREFIX);
        let address_str = address.to_string();
        let query_bytes = serde_json::to_vec(&serde_json::json!({"get_config": {}})).unwrap();
        let result = serde_json::to_vec(&serde_json::json!({
            "name": "test-contract",
            "version": "1.0.0",
            "config": {
                "enabled": true
            }
        }))
        .unwrap();
        let mock_address = address_str.clone();
        let mock_query = query_bytes.clone();
        let mock_result = result.clone();

        let mut mock_cosmos_client = MockCosmosClient::new();
        mock_cosmos_client.expect_clone().return_once(move || {
            let mut mock = MockCosmosClient::new();
            mock.expect_smart_contract_state()
                .with(predicate::eq(QuerySmartContractStateRequest {
                    address: mock_address,
                    query_data: mock_query,
                }))
                .return_once(move |_| Ok(QuerySmartContractStateResponse { data: mock_result }));

            mock
        });

        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            mock_cosmos_client,
        )
        .await;
        let req = Request::new(ContractStateRequest {
            contract: address_str,
            query: query_bytes,
        });
        let res = service.contract_state(req).await.unwrap().into_inner();

        assert_eq!(res.result, result);
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

        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .msg_queue_client(msg_queue_client)
            .cosmos_client(MockCosmosClient::new())
            .service_registry(TMAddress::random(PREFIX))
            .rewards(TMAddress::random(PREFIX))
            .config(Config::default())
            .build();

        let req = Request::new(AddressRequest {});
        let res = service.address(req).await.unwrap().into_inner();

        assert_eq!(res.address, expected_address.to_string());
    }

    #[tokio::test]
    async fn contracts_should_return_contracts_addresses_successfully() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;
        let chain_config = service.config.chains.first().unwrap();

        let req = Request::new(ContractsRequest {
            chain: "test-chain".to_string(),
        });
        let res = service.contracts(req).await.unwrap().into_inner();

        assert_eq!(
            res.voting_verifier,
            chain_config.voting_verifier.to_string()
        );
        assert_eq!(
            res.multisig_prover,
            chain_config.multisig_prover.to_string()
        );
        assert_eq!(res.service_registry, service.service_registry.to_string());
        assert_eq!(res.rewards, service.rewards.to_string());
        assert_eq!(res.multisig, chain_config.multisig.to_string());
    }

    #[tokio::test]
    async fn contracts_should_return_error_if_request_is_invalid() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;

        let req = Request::new(ContractsRequest {
            chain: "invalid_chain_name".to_string(),
        });
        let res = service.contracts(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn contracts_should_return_error_if_chain_not_found() {
        let (service, _) = setup(
            MockEventSub::new(),
            MockCosmosClient::new(),
            MockCosmosClient::new(),
        )
        .await;

        let req = Request::new(ContractsRequest {
            chain: "unexisting-chain".to_string(),
        });
        let res = service.contracts(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::NotFound));
    }

    fn subscribe_req(
        filters: Vec<ampd_proto::EventFilter>,
        include_block_begin_end: bool,
    ) -> Request<SubscribeRequest> {
        Request::new(SubscribeRequest {
            filters,
            include_block_begin_end,
        })
    }

    fn broadcast_req(msg: Option<Any>) -> Request<BroadcastRequest> {
        Request::new(BroadcastRequest { msg })
    }

    fn block_begin_event(height: u64) -> Event {
        Event::BlockBegin(height.try_into().unwrap())
    }

    fn block_end_event(height: u64) -> Event {
        Event::BlockEnd(height.try_into().unwrap())
    }

    fn abci_event(
        event_type: &str,
        attributes: Vec<(&str, &str)>,
        contract: Option<&str>,
    ) -> Event {
        Event::Abci {
            event_type: event_type.to_string(),
            attributes: attributes
                .into_iter()
                .chain(
                    contract
                        .into_iter()
                        .map(|contract| ("_contract_address", contract)),
                )
                .map(|(key, value)| {
                    (
                        key.to_string(),
                        serde_json::from_str(value)
                            .unwrap_or_else(|_| serde_json::Value::String(value.to_string())),
                    )
                })
                .collect(),
        }
    }

    fn dummy_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3, 4],
        }
    }
}
