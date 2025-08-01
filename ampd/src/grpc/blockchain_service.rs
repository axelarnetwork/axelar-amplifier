use std::fmt::Debug;
use std::pin::Pin;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    ContractStateRequest, ContractStateResponse, ContractsRequest, ContractsResponse,
    SubscribeRequest, SubscribeResponse,
};
use async_trait::async_trait;
use futures::{Stream, TryStreamExt};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::instrument;
use typed_builder::TypedBuilder;

use crate::grpc::reqs::Validate;
use crate::grpc::status;
use crate::{cosmos, event_sub};

#[derive(Debug, TypedBuilder)]
pub struct Service<E, C>
where
    E: event_sub::EventSub,
    C: cosmos::CosmosClient,
{
    event_sub: E,
    cosmos_client: C,
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

    async fn contracts(
        &self,
        _req: Request<ContractsRequest>,
    ) -> Result<Response<ContractsResponse>, Status> {
        Err(Status::unimplemented(
            "contracts method is not implemented yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use cosmrs::proto::cosmwasm::wasm::v1::{
        QuerySmartContractStateRequest, QuerySmartContractStateResponse,
    };
    use error_stack::report;
    use events::{self, Event};
    use futures::{stream, StreamExt};
    use mockall::predicate;
    use report::ErrorExt;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::{Code, Request};

    use super::*;
    use crate::cosmos::MockCosmosClient;
    use crate::event_sub::{self, MockEventSub};
    use crate::types::TMAddress;
    use crate::PREFIX;

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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();

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
        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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
        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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
        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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
        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(MockCosmosClient::new())
            .build();
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
    async fn contract_state_should_return_error_if_req_is_invalid() {
        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .cosmos_client(MockCosmosClient::new())
            .build();
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
        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .cosmos_client(MockCosmosClient::new())
            .build();
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
        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .cosmos_client(MockCosmosClient::new())
            .build();
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

        let service = Service::builder()
            .event_sub(MockEventSub::new())
            .cosmos_client(mock_cosmos_client)
            .build();
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

        let mock_event_sub = MockEventSub::new();
        let service = Service::builder()
            .event_sub(mock_event_sub)
            .cosmos_client(mock_cosmos_client)
            .build();
        let req = Request::new(ContractStateRequest {
            contract: address_str,
            query: query_bytes,
        });
        let res = service.contract_state(req).await.unwrap().into_inner();

        assert_eq!(res.result, result);
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
}
