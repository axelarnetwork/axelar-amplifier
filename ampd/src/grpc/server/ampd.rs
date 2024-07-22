use std::future;
use std::pin::Pin;

use async_trait::async_trait;
use events::Event;
use futures::{Stream, StreamExt, TryStreamExt};
use tonic::{Request, Response, Status};

use super::proto;
use crate::event_sub::EventSub;
use crate::queue::queued_broadcaster::BroadcasterClient;

impl From<Event> for proto::subscribe_response::Event {
    fn from(event: Event) -> Self {
        match event {
            Event::BlockBegin(height) => Self::BlockBegin(proto::EventBlockBegin {
                height: height.into(),
            }),
            Event::BlockEnd(height) => Self::BlockEnd(proto::EventBlockEnd {
                height: height.into(),
            }),
            Event::Abci {
                event_type,
                attributes,
            } => Self::Abci(proto::Event {
                event_type,
                event_attributes: attributes
                    .into_iter()
                    .map(|(key, value)| (key, value.to_string()))
                    .collect(),
            }),
        }
    }
}

impl proto::SubscribeRequest {
    fn matches(&self, event: &Event) -> bool {
        match event {
            Event::BlockBegin(_) | Event::BlockEnd(_) => self.include_block_begin_end,
            Event::Abci {
                event_type,
                attributes,
            } => {
                self.event_filters.is_empty()
                    || self.event_filters.iter().any(|filter| {
                        filter.event_type == *event_type
                            && filter.event_attributes.iter().all(|(key, value)| {
                                attributes.get(key).map(|v| v == value).unwrap_or_default()
                            })
                    })
            }
        }
    }
}

pub struct Server<S, B>
where
    S: EventSub,
    B: BroadcasterClient,
{
    event_subscriber: S,
    broadcaster: B,
}

impl<S, B> Server<S, B>
where
    S: EventSub,
    B: BroadcasterClient,
{
    pub fn new(event_subscriber: S, broadcaster: B) -> Self {
        Self {
            event_subscriber,
            broadcaster,
        }
    }
}

#[async_trait]
impl<S, B> proto::ampd_server::Ampd for Server<S, B>
where
    S: EventSub + Send + Sync + 'static,
    B: BroadcasterClient + Send + Sync + 'static,
{
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<proto::SubscribeResponse, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        req: Request<proto::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = req.into_inner();
        let stream = self
            .event_subscriber
            .subscribe()
            .filter(move |event| {
                future::ready(
                    event
                        .as_ref()
                        .map(|event| req.matches(event))
                        .unwrap_or(true),
                )
            })
            .map_ok(Into::into)
            .map_ok(|event| proto::SubscribeResponse { event: Some(event) })
            .map_err(|err| Status::internal(format!("failed to subscribe to events: {}", err)));

        Ok(Response::new(Box::pin(stream)))
    }

    async fn broadcast(
        &self,
        req: Request<proto::BroadcastRequest>,
    ) -> Result<Response<proto::BroadcastResponse>, Status> {
        let req = req.into_inner();
        let msg = req.msg.ok_or(Status::invalid_argument("missing msg"))?;

        self.broadcaster
            .broadcast(msg)
            .await
            .map_err(|err| Status::internal(format!("failed to broadcast message: {}", err)))?;

        Ok(Response::new(proto::BroadcastResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use cosmrs::bank::MsgSend;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Any};
    use error_stack::Report;
    use events::Event;
    use serde_json::Map;
    use tokio::test;
    use tokio::time::interval;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::StreamExt;
    use tonic::Code;

    use super::proto::ampd_server::Ampd;
    use super::proto::{self};
    use super::Server;
    use crate::event_sub::MockEventSub;
    use crate::queue::queued_broadcaster;
    use crate::queue::queued_broadcaster::MockBroadcasterClient;

    #[test]
    async fn subscribe_should_return_stream_of_error_when_event_subscriber_fails() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut event_sub = MockEventSub::default();
        event_sub
            .expect_subscribe()
            .return_once(|| Box::pin(ReceiverStream::new(rx)));
        let server = Server::new(event_sub, MockBroadcasterClient::default());

        let req = tonic::Request::new(proto::SubscribeRequest::default());
        let mut res = server.subscribe(req).await.unwrap().into_inner();

        tx.send(Err(Report::new(BroadcastStreamRecvError::Lagged(10))))
            .await
            .unwrap();
        assert_eq!(
            res.next().await.unwrap().unwrap_err().code(),
            Code::Internal
        );
    }

    #[test]
    async fn subscribe_should_return_stream_of_all_events_when_no_filter_is_given() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut event_sub = MockEventSub::default();
        event_sub
            .expect_subscribe()
            .return_once(|| Box::pin(ReceiverStream::new(rx)));
        let server = Server::new(event_sub, MockBroadcasterClient::default());

        let req = tonic::Request::new(proto::SubscribeRequest {
            include_block_begin_end: true,
            event_filters: vec![],
        });
        let mut res = server.subscribe(req).await.unwrap().into_inner();

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: Map::new(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(res.next().await.unwrap().unwrap().event, Some(event.into()));

        let event = Event::Abci {
            event_type: "some_other_event".into(),
            attributes: serde_json::from_str("{\"key_1\":\"value_1\",\"key_2\":\"value_2\"}")
                .unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(res.next().await.unwrap().unwrap().event, Some(event.into()));

        let event = Event::BlockBegin(1u32.into());
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(res.next().await.unwrap().unwrap().event, Some(event.into()));

        let event = Event::BlockEnd(1u32.into());
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(res.next().await.unwrap().unwrap().event, Some(event.into()));
    }

    #[test]
    async fn subscribe_should_not_return_block_begin_end_event_when_filter_excludes_them() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut event_sub = MockEventSub::default();
        event_sub
            .expect_subscribe()
            .return_once(|| Box::pin(ReceiverStream::new(rx)));
        let server = Server::new(event_sub, MockBroadcasterClient::default());

        let req = tonic::Request::new(proto::SubscribeRequest::default());
        let res = server
            .subscribe(req)
            .await
            .unwrap()
            .into_inner()
            .timeout_repeating(interval(Duration::from_secs(1)));
        tokio::pin!(res);

        let event = Event::BlockBegin(1u32.into());
        tx.send(Ok(event)).await.unwrap();
        assert!(res.next().await.unwrap().is_err());

        let event = Event::BlockEnd(1u32.into());
        tx.send(Ok(event)).await.unwrap();
        assert!(res.next().await.unwrap().is_err());

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: Map::new(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            res.next().await.unwrap().unwrap().unwrap().event,
            Some(event.into())
        );
    }

    #[test]
    async fn subscribe_should_return_only_events_matching_filter() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut event_sub = MockEventSub::default();
        event_sub
            .expect_subscribe()
            .return_once(|| Box::pin(ReceiverStream::new(rx)));
        let server = Server::new(event_sub, MockBroadcasterClient::default());

        let req = tonic::Request::new(proto::SubscribeRequest {
            include_block_begin_end: true,
            event_filters: vec![
                proto::Event {
                    event_type: "some_event".into(),
                    event_attributes: vec![("key_1".to_string(), "value_1".to_string())]
                        .into_iter()
                        .collect(),
                },
                proto::Event {
                    event_type: "some_event".into(),
                    event_attributes: vec![("key_2".to_string(), "value_2".to_string())]
                        .into_iter()
                        .collect(),
                },
                proto::Event {
                    event_type: "some_other_event".into(),
                    event_attributes: HashMap::new(),
                },
            ],
        });
        let res = server
            .subscribe(req)
            .await
            .unwrap()
            .into_inner()
            .timeout_repeating(interval(Duration::from_secs(1)));
        tokio::pin!(res);

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_1\":\"value_1\"}").unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            res.next().await.unwrap().unwrap().unwrap().event,
            Some(event.into())
        );

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_2\":\"value_2\",\"key_3\":\"value_3\"}")
                .unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            res.next().await.unwrap().unwrap().unwrap().event,
            Some(event.into())
        );

        let event = Event::Abci {
            event_type: "some_other_event".into(),
            attributes: serde_json::from_str("{\"key_3\":\"value_3\"}").unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            res.next().await.unwrap().unwrap().unwrap().event,
            Some(event.into())
        );

        let event = Event::Abci {
            event_type: "some_bad_event".into(),
            attributes: Map::new(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert!(res.next().await.unwrap().is_err());

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_1\":\"value_2\"}").unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert!(res.next().await.unwrap().is_err());

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_2\":\"value_1\"}").unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert!(res.next().await.unwrap().is_err());

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_3\":\"value_3\"}").unwrap(),
        };
        tx.send(Ok(event.clone())).await.unwrap();
        assert!(res.next().await.unwrap().is_err());
    }

    #[test]
    async fn broadcast_should_fail_if_msg_is_missing() {
        let server = Server::new(MockEventSub::default(), MockBroadcasterClient::default());

        let req = tonic::Request::new(proto::BroadcastRequest { msg: None });
        let res = server.broadcast(req).await.unwrap_err();

        assert_eq!(res.code(), Code::InvalidArgument);
    }

    #[test]
    async fn broadcast_should_fail_if_fails_to_broadcast() {
        let mut broadcaster = MockBroadcasterClient::default();
        broadcaster
            .expect_broadcast()
            .return_once(|_| Err(Report::new(queued_broadcaster::Error::Broadcast)));
        let server = Server::new(MockEventSub::default(), broadcaster);

        let req = tonic::Request::new(proto::BroadcastRequest {
            msg: Some(dummy_msg()),
        });
        let res = server.broadcast(req).await.unwrap_err();

        assert_eq!(res.code(), Code::Internal);
    }

    #[test]
    async fn broadcast_should_succeed() {
        let mut broadcaster = MockBroadcasterClient::default();
        broadcaster.expect_broadcast().return_once(|_| Ok(()));
        let server = Server::new(MockEventSub::default(), broadcaster);

        let req = tonic::Request::new(proto::BroadcastRequest {
            msg: Some(dummy_msg()),
        });
        let res = server.broadcast(req).await.unwrap();

        assert_eq!(res.get_ref(), &proto::BroadcastResponse {});
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
