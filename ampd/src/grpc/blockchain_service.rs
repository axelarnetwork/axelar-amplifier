use std::fmt::Debug;
use std::pin::Pin;
#[cfg(not(feature = "dummy-grpc-broadcast"))]
use std::sync::Arc;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractStateRequest,
    ContractStateResponse, ContractsRequest, ContractsResponse, LatestBlockHeightRequest,
    LatestBlockHeightResponse, SubscribeRequest, SubscribeResponse,
};
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
#[cfg(not(feature = "dummy-grpc-broadcast"))]
use axelar_wasm_std::FnExt;
#[cfg(not(feature = "dummy-grpc-broadcast"))]
use futures::TryFutureExt;
use futures::{Stream, TryStreamExt};
use monitoring::metrics::Msg;
use serde::{Deserialize, Serialize};
use tokio::sync::watch::Receiver;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::instrument;
#[cfg(feature = "dummy-grpc-broadcast")]
use tracing::{info, warn};
use typed_builder::TypedBuilder;

use crate::grpc::reqs::Validate;
use crate::grpc::status;
use crate::types::TMAddress;
use crate::{broadcast, cosmos, event_sub, monitoring};

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
    latest_block_height: Receiver<u64>,
    config: Config,
    monitoring_client: monitoring::Client,
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

    // TODO: Remove the feature flag when analysis is complete and restore original broadcast
    #[cfg_attr(not(feature = "dummy-grpc-broadcast"), instrument)]
    async fn broadcast(
        &self,
        req: Request<BroadcastRequest>,
    ) -> Result<Response<BroadcastResponse>, Status> {
        let msg = req
            .validate()
            .inspect_err(status::log("invalid broadcast request"))
            .map_err(status::StatusExt::into_status)?;

        #[cfg(feature = "dummy-grpc-broadcast")]
        {
            match broadcast::deserialize_protobuf(&msg.value) {
                Ok(deserialized_values) => {
                    info!(
                        msg_type_url = %msg.type_url,
                        msg_value_plain = ?msg.value,
                        msg_value_deserialized = %deserialized_values,
                        msg_value_hex = %hex::encode(&msg.value),
                        "gRPC EVM handler message details"
                    );
                }
                Err(e) => {
                    warn!(
                        msg_type_url = %msg.type_url,
                        msg_value_plain = ?msg.value,
                        msg_value_hex = %hex::encode(&msg.value),
                        error = %e,
                        "failed to parse gRPC EVM handler protobuf structure, showing raw data"
                    );
                }
            }

            Ok(Response::new(BroadcastResponse {
                tx_hash: "dummy_tx_hash_for_testing".to_string(),
                index: 0,
            }))
        }

        #[cfg(not(feature = "dummy-grpc-broadcast"))]
        {
            self.msg_queue_client
                .clone()
                .enqueue(msg)
                .inspect_err(|_| {
                    self.monitoring_client
                        .metrics()
                        .record_metric(Msg::MessageEnqueueError);
                })
                .map_err(Arc::new)
                .and_then(|rx| rx)
                .await
                .map(|(tx_hash, index)| BroadcastResponse { tx_hash, index })
                .map(Response::new)
                .inspect_err(|err| err.as_ref().then(status::log("message broadcast error")))
                .map_err(|err| status::StatusExt::into_status(err.as_ref()))
        }
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
            .inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::GrpcServiceError);
                status::log("query contract state error")(err)
            })
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

    async fn latest_block_height(
        &self,
        _req: Request<LatestBlockHeightRequest>,
    ) -> Result<Response<LatestBlockHeightResponse>, Status> {
        Ok(Response::new(LatestBlockHeightResponse {
            height: *self.latest_block_height.borrow(),
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
    use cosmrs::proto::cosmwasm::wasm::v1::QuerySmartContractStateResponse;
    use cosmrs::{Any, Gas};
    use error_stack::report;
    use events::{self, Event};
    use futures::future::join_all;
    use futures::{stream, StreamExt};
    use mockall::{predicate, Sequence};
    use report::ErrorExt;
    use tokio::sync::watch;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::{Code, Request};

    use super::*;
    use crate::broadcast::DecCoin;
    use crate::cosmos::MockCosmosClient;
    use crate::event_sub::{self, MockEventSub};
    use crate::monitoring::test_utils;
    use crate::types::{random_cosmos_public_key, CosmosPublicKey, TMAddress};
    use crate::PREFIX;

    const GAS_CAP: Gas = 10000;
    const GAS_PRICE_DENOM: &str = "uaxl";
    pub struct TestBuilder {
        monitoring_client: monitoring::Client,
        pub_key: CosmosPublicKey,
        base_account: BaseAccount,
        broadcaster_cosmos_client: MockCosmosClient,
        custom_block_height_rx: Receiver<u64>,
        expected_events: Vec<Event>,
        expected_simulate_response: Option<SimulateResponse>,
        expected_contract_state_response: Option<QuerySmartContractStateResponse>,
        event_subscription_error: Option<event_sub::Error>,
        simulate_error: Option<Status>,
        contract_state_error: Option<cosmos::Error>,
    }

    impl Default for TestBuilder {
        fn default() -> Self {
            let (monitoring_client, _) = test_utils::monitoring_client();
            let pub_key = random_cosmos_public_key();
            let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
            let base_account = BaseAccount {
                address: address.to_string(),
                pub_key: None,
                account_number: 42,
                sequence: 10,
            };

            let mut broadcaster_cosmos_client = MockCosmosClient::new();
            let mut seq = Sequence::new();
            let base_account_clone = base_account.clone();
            broadcaster_cosmos_client
                .expect_account()
                .once()
                .in_sequence(&mut seq)
                .return_once(move |_| {
                    Ok(QueryAccountResponse {
                        account: Some(Any::from_msg(&base_account_clone).unwrap()),
                    })
                });

            broadcaster_cosmos_client
                .expect_balance()
                .once()
                .with(predicate::eq(QueryBalanceRequest {
                    address: address.to_string(),
                    denom: GAS_PRICE_DENOM.to_string(),
                }))
                .in_sequence(&mut seq)
                .return_once(move |_| {
                    Ok(QueryBalanceResponse {
                        balance: Some(Coin {
                            denom: GAS_PRICE_DENOM.to_string(),
                            amount: "1000000".to_string(),
                        }),
                    })
                });

            Self {
                monitoring_client,
                pub_key,
                base_account: base_account.clone(),
                broadcaster_cosmos_client,
                custom_block_height_rx: watch::channel(0).1,
                expected_events: vec![],
                expected_simulate_response: None,
                expected_contract_state_response: None,
                event_subscription_error: None,
                simulate_error: None,
                contract_state_error: None,
            }
        }
    }

    impl TestBuilder {
        pub fn with_expected_events(mut self, events: Vec<Event>) -> Self {
            self.expected_events = events;
            self
        }

        pub fn with_expected_simulate_response(mut self, response: SimulateResponse) -> Self {
            self.expected_simulate_response = Some(response);
            self
        }

        pub fn with_expected_contract_state_response(
            mut self,
            response: QuerySmartContractStateResponse,
        ) -> Self {
            self.expected_contract_state_response = Some(response);
            self
        }

        pub fn with_monitoring_client(mut self, client: monitoring::Client) -> Self {
            self.monitoring_client = client;
            self
        }

        pub fn with_custom_block_height_rx(mut self, rx: Receiver<u64>) -> Self {
            self.custom_block_height_rx = rx;
            self
        }

        pub fn with_event_subscription_error(mut self, error: event_sub::Error) -> Self {
            self.event_subscription_error = Some(error);
            self
        }

        pub fn with_simulate_error(mut self, error: Status) -> Self {
            self.simulate_error = Some(error);
            self
        }

        pub fn with_contract_state_error(mut self, error: cosmos::Error) -> Self {
            self.contract_state_error = Some(error);
            self
        }

        pub async fn build(
            self,
        ) -> (
            Service<MockEventSub, MockCosmosClient>,
            impl Stream<Item = nonempty::Vec<broadcast::QueueMsg>>,
        ) {
            let mut broadcaster_cosmos_client = self.broadcaster_cosmos_client;
            let mut cosmos_client = MockCosmosClient::new();
            let mut event_sub = MockEventSub::new();

            let stream = match self.event_subscription_error {
                Some(error) => tokio_stream::once(Err(report!(error))).boxed(),
                None => {
                    stream::iter(self.expected_events.clone().into_iter().map(Result::Ok)).boxed()
                }
            };
            event_sub.expect_subscribe().return_once(move || stream);

            if let Some(simulate_response) = self.expected_simulate_response {
                broadcaster_cosmos_client.expect_clone().returning(move || {
                    let mut mock_cosmos_client = MockCosmosClient::new();
                    let base_account_clone = self.base_account.clone();
                    mock_cosmos_client.expect_account().return_once(move |_| {
                        Ok(QueryAccountResponse {
                            account: Some(Any::from_msg(&base_account_clone).unwrap()),
                        })
                    });
                    let simulate_response_clone = simulate_response.clone();
                    mock_cosmos_client
                        .expect_simulate()
                        .return_once(move |_| Ok(simulate_response_clone));

                    mock_cosmos_client
                });
            } else if let Some(simulate_error) = self.simulate_error {
                broadcaster_cosmos_client.expect_clone().returning(move || {
                    let mut mock_cosmos_client = MockCosmosClient::new();
                    let base_account_clone = self.base_account.clone();
                    mock_cosmos_client.expect_account().return_once(move |_| {
                        Ok(QueryAccountResponse {
                            account: Some(Any::from_msg(&base_account_clone).unwrap()),
                        })
                    });
                    let simulate_error_clone = simulate_error.clone();
                    mock_cosmos_client
                        .expect_simulate()
                        .return_once(move |_| Err(simulate_error_clone.into_report()));

                    mock_cosmos_client
                });
            }

            match (
                self.expected_contract_state_response,
                self.contract_state_error,
            ) {
                (Some(contract_state_response), None) => {
                    cosmos_client.expect_clone().return_once(move || {
                        let mut mock = MockCosmosClient::new();
                        mock.expect_smart_contract_state()
                            .return_once(move |_| Ok(contract_state_response));
                        mock
                    });
                }
                (None, Some(contract_state_error)) => {
                    cosmos_client.expect_clone().return_once(move || {
                        let mut mock = MockCosmosClient::new();
                        mock.expect_smart_contract_state()
                            .return_once(move |_| Err(report!(contract_state_error)));
                        mock
                    });
                }
                _ => {}
            }

            let broadcaster = broadcast::Broadcaster::builder()
                .client(broadcaster_cosmos_client)
                .chain_id("chain_id".try_into().unwrap())
                .pub_key(self.pub_key)
                .gas_adjustment(1.5)
                .gas_price(DecCoin::new(0.025, GAS_PRICE_DENOM).unwrap())
                .build()
                .await
                .unwrap();

            let (msg_queue, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
                broadcaster,
                100,
                GAS_CAP,
                Duration::from_secs(1),
                self.monitoring_client.clone(),
            );

            let service = Service::builder()
                .event_sub(event_sub)
                .msg_queue_client(msg_queue_client)
                .cosmos_client(cosmos_client)
                .service_registry(TMAddress::random(PREFIX))
                .rewards(TMAddress::random(PREFIX))
                .latest_block_height(self.custom_block_height_rx)
                .config(Config {
                    chains: vec![ChainConfig {
                        chain_name: chain_name!("test-chain"),
                        voting_verifier: TMAddress::random(PREFIX),
                        multisig_prover: TMAddress::random(PREFIX),
                        multisig: TMAddress::random(PREFIX),
                    }],
                })
                .monitoring_client(self.monitoring_client)
                .build();

            (service, msg_queue)
        }
    }

    #[tokio::test]
    async fn subscribe_should_stream_events_successfully() {
        let expected = vec![
            block_begin_event(100),
            abci_event("test_event", vec![("key1", "value1")], None),
            block_end_event(100),
        ];

        let (service, _) = TestBuilder::default()
            .with_expected_events(expected.clone())
            .build()
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
        let (service, _) = TestBuilder::default().build().await;
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
        let (service, _) = TestBuilder::default()
            .with_event_subscription_error(event_sub::Error::LatestBlockQuery)
            .build()
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
        let (service, _) = TestBuilder::default()
            .with_event_subscription_error(event_sub::Error::BlockResultsQuery {
                block: 100u32.into(),
            })
            .build()
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
        let (service, _) = TestBuilder::default()
            .with_event_subscription_error(event_sub::Error::EventDecoding {
                block: 100u32.into(),
            })
            .build()
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
        let (service, _) = TestBuilder::default()
            .with_event_subscription_error(BroadcastStreamRecvError::Lagged(10).into())
            .build()
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

        let (service, _) = TestBuilder::default()
            .with_expected_events(events)
            .build()
            .await;

        let filter = ampd_proto::EventFilter {
            r#type: "event_type_2".to_string(),
            ..Default::default()
        };
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

        let filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: expected.contract_address().unwrap().to_string(),
        };
        let (service, _) = TestBuilder::default()
            .with_expected_events(events)
            .build()
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

        let (service, _) = TestBuilder::default()
            .with_expected_events(events)
            .build()
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

        let filter_1 = ampd_proto::EventFilter {
            r#type: "event_1".to_string(),
            ..Default::default()
        };
        let filter_2 = ampd_proto::EventFilter {
            contract: expected[1].contract_address().unwrap().to_string(),
            ..Default::default()
        };
        let (service, _) = TestBuilder::default()
            .with_expected_events(events)
            .build()
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
        let (service, _) = TestBuilder::default().build().await;
        let res = service.broadcast(broadcast_req(None)).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    #[cfg_attr(feature = "dummy-grpc-broadcast", ignore)]
    async fn broadcast_should_return_error_if_enqueue_failed() {
        let (service, _) = TestBuilder::default()
            .with_simulate_error(Status::internal("simulate error"))
            .build()
            .await;
        let res = service.broadcast(broadcast_req(Some(dummy_msg()))).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    #[cfg_attr(feature = "dummy-grpc-broadcast", ignore)]
    async fn broadcast_should_return_error_if_broadcast_failed() {
        let simulate_response = SimulateResponse {
            gas_info: Some(GasInfo {
                gas_wanted: GAS_CAP + 1,
                gas_used: GAS_CAP + 1,
            }),
            result: None,
        };

        let (service, msg_queue) = TestBuilder::default()
            .with_expected_simulate_response(simulate_response)
            .build()
            .await;
        tokio::spawn(async move {
            tokio::pin!(msg_queue);
            while msg_queue.next().await.is_some() {}
        });
        let res = service.broadcast(broadcast_req(Some(dummy_msg()))).await;
        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    #[cfg_attr(feature = "dummy-grpc-broadcast", ignore)]
    async fn broadcast_should_return_tx_hash_and_index() {
        let tx_hash = "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b";
        let msg_count = 10;

        let simulate_response = SimulateResponse {
            gas_info: Some(GasInfo {
                gas_wanted: GAS_CAP / msg_count as u64,
                gas_used: GAS_CAP / msg_count as u64,
            }),
            result: None,
        };

        let (service, msg_queue) = TestBuilder::default()
            .with_expected_simulate_response(simulate_response)
            .build()
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

        tokio::pin!(msg_queue);
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
        let (service, _) = TestBuilder::default().build().await;
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
        let (service, _) = TestBuilder::default().build().await;
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
        let (service, _) = TestBuilder::default().build().await;
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

        let _mock_address = address_str.clone();
        let _mock_query = query_bytes.clone();

        let (service, _) = TestBuilder::default()
            .with_contract_state_error(cosmos::Error::QueryContractState(
                "execution error".to_string(),
            ))
            .build()
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
        let _mock_address = address_str.clone();
        let _mock_query = query_bytes.clone();
        let _mock_result = result.clone();

        let contract_state_response = QuerySmartContractStateResponse {
            data: result.clone(),
        };

        let (service, _) = TestBuilder::default()
            .with_expected_contract_state_response(contract_state_response)
            .build()
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
        let (monitoring_client, _) = test_utils::monitoring_client();

        let (_, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
            broadcaster,
            10,
            1000u64,
            Duration::from_secs(1),
            monitoring_client,
        );
        let (monitoring_client, _) = test_utils::monitoring_client();

        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .msg_queue_client(msg_queue_client)
            .cosmos_client(MockCosmosClient::new())
            .service_registry(TMAddress::random(PREFIX))
            .rewards(TMAddress::random(PREFIX))
            .latest_block_height(watch::channel(0).1)
            .config(Config::default())
            .monitoring_client(monitoring_client)
            .build();

        let req = Request::new(AddressRequest {});
        let res = service.address(req).await.unwrap().into_inner();

        assert_eq!(res.address, expected_address.to_string());
    }

    #[tokio::test]
    async fn contracts_should_return_contracts_addresses_successfully() {
        let (service, _) = TestBuilder::default().build().await;
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
        let (service, _) = TestBuilder::default().build().await;

        let req = Request::new(ContractsRequest {
            chain: "invalid_chain_name".to_string(),
        });
        let res = service.contracts(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::InvalidArgument));
    }

    #[tokio::test]
    async fn contracts_should_return_error_if_chain_not_found() {
        let (service, _) = TestBuilder::default().build().await;

        let req = Request::new(ContractsRequest {
            chain: "unexisting-chain".to_string(),
        });
        let res = service.contracts(req).await;

        assert!(res.is_err_and(|status| status.code() == Code::NotFound));
    }

    #[tokio::test]
    async fn latest_block_height_should_return_correct_height() {
        let (tx, rx) = watch::channel(100);
        let (service, _) = TestBuilder::default()
            .with_custom_block_height_rx(rx)
            .build()
            .await;

        let response = service
            .latest_block_height(Request::new(LatestBlockHeightRequest {}))
            .await
            .unwrap();
        assert_eq!(response.into_inner().height, 100);

        tx.send(200).unwrap();

        let second_response = service
            .latest_block_height(Request::new(LatestBlockHeightRequest {}))
            .await
            .unwrap();
        assert_eq!(second_response.into_inner().height, 200);
    }

    #[tokio::test]
    #[cfg_attr(feature = "dummy-grpc-broadcast", ignore)]
    async fn should_record_enqueue_err_when_simulate_failed() {
        let (monitoring_client, mut metrics_rx) = test_utils::monitoring_client();
        let (service, _) = TestBuilder::default()
            .with_simulate_error(Status::internal("simulate error"))
            .with_monitoring_client(monitoring_client)
            .build()
            .await;

        let _ = service.broadcast(broadcast_req(Some(dummy_msg()))).await;

        let res = metrics_rx.recv().await.unwrap();
        assert_eq!(res, Msg::MessageEnqueueError);

        assert!(metrics_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_record_grpc_service_err_when_contract_state_failed() {
        let address = TMAddress::random(PREFIX);
        let address_str = address.to_string();
        let query_bytes = serde_json::to_vec(&serde_json::json!({"get_config": {}})).unwrap();

        let _mock_address = address_str.clone();
        let _mock_query = query_bytes.clone();

        let (monitoring_client, mut metrics_rx) = test_utils::monitoring_client();
        let (service, _) = TestBuilder::default()
            .with_contract_state_error(cosmos::Error::QueryContractState(
                "execution error".to_string(),
            ))
            .with_monitoring_client(monitoring_client)
            .build()
            .await;

        let req = Request::new(ContractStateRequest {
            contract: address_str,
            query: query_bytes,
        });

        let _ = service.contract_state(req).await;

        let res = metrics_rx.recv().await.unwrap();
        assert_eq!(res, Msg::GrpcServiceError);

        assert!(metrics_rx.try_recv().is_err());
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
