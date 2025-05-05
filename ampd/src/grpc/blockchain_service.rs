use std::pin::Pin;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractsRequest,
    ContractsResponse, QueryRequest, QueryResponse, SubscribeRequest, SubscribeResponse,
};
use async_trait::async_trait;
use futures::{Stream, TryStreamExt};
use report::LoggableError;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::error;
use valuable::Valuable;

use super::error::ErrorExt;
use crate::event_sub;
use crate::grpc::event_filters;

pub struct Service<E>
where
    E: event_sub::EventSub,
{
    event_sub: E,
}

impl<E> Service<E>
where
    E: event_sub::EventSub,
{
    pub fn new(event_sub: E) -> Self {
        Self { event_sub }
    }
}

#[async_trait]
impl<E> BlockchainService for Service<E>
where
    E: event_sub::EventSub + Send + Sync + 'static,
{
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, Status>> + Send>>;

    async fn subscribe(
        &self,
        req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let SubscribeRequest {
            filters,
            include_block_begin_end,
        } = req.into_inner();

        let filters: event_filters::EventFilters = (filters, include_block_begin_end)
            .try_into()
            .inspect_err(|err| {
                error!(
                    err = LoggableError::from(err).as_value(),
                    "invalid event filters provided for event subscription"
                );
            })
            .map_err(ErrorExt::into_status)?;

        Ok(Response::new(Box::pin(
            self.event_sub
                .subscribe()
                .filter(move |event| match event {
                    Ok(event) => filters.filter(event),
                    Err(_) => true,
                })
                .map_ok(Into::into)
                .map_ok(|event| ampd_proto::SubscribeResponse { event: Some(event) })
                .inspect_err(|err| {
                    error!(
                        err = LoggableError::from(err).as_value(),
                        "event subscription error"
                    );
                })
                .map_err(ErrorExt::into_status),
        )))
    }

    async fn broadcast(
        &self,
        _req: Request<BroadcastRequest>,
    ) -> Result<Response<BroadcastResponse>, Status> {
        todo!("implement broadcast method")
    }

    async fn query(&self, _req: Request<QueryRequest>) -> Result<Response<QueryResponse>, Status> {
        todo!("implement query method")
    }

    async fn address(
        &self,
        _req: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        todo!("implement address method")
    }

    async fn contracts(
        &self,
        _req: Request<ContractsRequest>,
    ) -> Result<Response<ContractsResponse>, Status> {
        todo!("implement contracts method")
    }
}

#[cfg(test)]
mod tests {
    use error_stack::report;
    use events::{self, Event};
    use futures::{stream, StreamExt};
    use report::ErrorExt;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tonic::{Code, Request};

    use super::*;
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

        let service = Service::new(mock_event_sub);
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
        let mock_event_sub = MockEventSub::new();

        let service = Service::new(mock_event_sub);
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

        let service = Service::new(mock_event_sub);
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

        let service = Service::new(mock_event_sub);
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

        let service = Service::new(mock_event_sub);
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

        let service = Service::new(mock_event_sub);
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
        let service = Service::new(mock_event_sub);
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
        let service = Service::new(mock_event_sub);
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

        let service = Service::new(mock_event_sub);
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
        let service = Service::new(mock_event_sub);
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
