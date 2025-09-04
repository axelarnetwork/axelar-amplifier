use std::fmt::{Debug, Display};
use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{Context, ResultExt};
use events::{AbciEventTypeFilter, Event};
use futures::{pin_mut, Stream};
use mockall::automock;
use report::ErrorExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::interval;
use tokio_stream::{Elapsed, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, instrument};
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::future::{with_retry, RetryPolicy};
use crate::grpc::client;

#[automock(
    type Err = Error;
    type Event = Event;
)]
#[async_trait]
pub trait EventHandler: Send + Sync {
    type Err: Context;
    type Event: TryFrom<Event>;

    async fn handle(
        &self,
        event: &Self::Event,
        token: CancellationToken,
    ) -> error_stack::Result<Vec<Any>, Self::Err>;

    fn subscription_params(&self) -> SubscriptionParams;
}

pub struct SubscriptionParams {
    event_filters: Vec<AbciEventTypeFilter>,
    include_block_begin_end: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(with = "humantime_serde")]
    pub stream_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stream_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to retrieve events stream from the client")]
    EventStream,

    #[error("timeout while waiting for event stream")]
    StreamTimeout(#[from] Elapsed),

    #[error("unable to parse event of type")]
    EventConversion,

    #[error("error when handling event messages")]
    HandlerFailed,

    #[error("error when broadcasting message")]
    BroadcastFailed,
}

#[derive(Debug, TypedBuilder)]
pub struct HandlerTask<H>
where
    H: EventHandler,
    <H::Event as TryFrom<Event>>::Error: Context,
    H::Event: Display,
{
    handler: H,
    config: Config,
    #[builder(default = RetryPolicy::NoRetry)]
    handler_retry_policy: RetryPolicy,
}

impl<H> HandlerTask<H>
where
    H: EventHandler + Debug,
    <H::Event as TryFrom<Event>>::Error: Context,
    H::Event: Display + Debug,
{
    pub async fn run(
        self,
        client: &mut impl client::Client,
        token: CancellationToken,
    ) -> error_stack::Result<(), Error> {
        let stream = self.subscribe_to_stream(client, token.clone()).await?;

        pin_mut!(stream);
        while let Some(element) = stream.next().await {
            self.process_stream(element, client, token.clone()).await;
        }

        Ok(())
    }

    async fn subscribe_to_stream(
        &self,
        client: &mut impl client::Client,
        token: CancellationToken,
    ) -> error_stack::Result<impl Stream<Item = error_stack::Result<Event, Error>>, Error> {
        let subscription_params = self.handler.subscription_params();

        let stream = client
            .subscribe(
                subscription_params.event_filters,
                subscription_params.include_block_begin_end,
            )
            .await
            .change_context(Error::EventStream)?
            .take_while(move |_| !token.is_cancelled())
            .timeout_repeating(interval(self.config.stream_timeout))
            .map(|event| match event {
                Ok(Ok(event)) => Ok(event),
                Ok(Err(err)) => Err(err.change_context(Error::EventStream)),
                Err(elapsed) => Err(Error::StreamTimeout(elapsed).into_report()),
            });

        Ok(stream)
    }

    async fn process_stream(
        &self,
        element: error_stack::Result<Event, Error>,
        client: &mut impl client::Client,
        token: CancellationToken,
    ) {
        if let Some(msgs) = self.process_event(element, token.clone()).await {
            Self::broadcast_msgs(client, msgs, token.clone()).await;
        }
    }

    async fn process_event(
        &self,
        element: error_stack::Result<Event, Error>,
        token: CancellationToken,
    ) -> Option<Vec<Any>> {
        let event = element
            .inspect(Self::log_block_boundary)
            .inspect_err(|err| {
                error!(
                    err = report::LoggableError::from(err).as_value(),
                    "failed to get event from stream"
                )
            })
            .ok()?;
        let parsed = Self::parse_event(event)?;
        self.handle_event(parsed, token).await
    }

    #[instrument]
    fn parse_event(event: Event) -> Option<H::Event> {
        H::Event::try_from(event.clone())
            .change_context(Error::EventConversion)
            .ok()
    }

    fn log_block_boundary(event: &Event) {
        match event {
            Event::BlockBegin(height) => {
                info!(height = height.value(), "handler started processing block");
            }
            Event::BlockEnd(height) => {
                info!(height = height.value(), "handler finished processing block");
            }
            _ => {}
        }
    }

    #[instrument]
    async fn handle_event(&self, event: H::Event, token: CancellationToken) -> Option<Vec<Any>> {
        with_retry(
            || self.handler.handle(&event, token.clone()),
            self.handler_retry_policy,
        )
        .await
        .ok()
    }

    async fn broadcast_msgs(
        client: &mut impl client::Client,
        msgs: Vec<Any>,
        token: CancellationToken,
    ) {
        for msg in msgs {
            if token.is_cancelled() {
                return;
            }
            if let Err(err) = client.broadcast(msg.clone()).await {
                error!(
                    err = report::LoggableError::from(&err).as_value(),
                    msg_type = msg.type_url.as_value(),
                    msg_value = hex::encode(&msg.value).as_value(),
                    "failed to broadcast message"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use error_stack::report;

    use super::*;
    use crate::grpc::client::types::BroadcastClientResponse;
    use crate::grpc::client::MockClient;
    use crate::grpc::error::{AppError, Error as ClientError};

    fn setup_handler() -> MockEventHandler {
        let mut handler = MockEventHandler::new();
        handler
            .expect_subscription_params()
            .returning(|| SubscriptionParams {
                event_filters: vec![AbciEventTypeFilter {
                    event_type: "test_event".to_string(),
                }],
                include_block_begin_end: true,
            });
        handler
    }

    fn mock_client_subscribe_with_events(events: Vec<Event>) -> MockClient {
        let mut mock_client = MockClient::new();
        mock_client
            .expect_subscribe()
            .times(1)
            .returning(move |_, _| {
                let result_events: Vec<error_stack::Result<Event, ClientError>> =
                    events.clone().into_iter().map(Ok).collect();
                Ok(tokio_stream::iter(result_events))
            });
        mock_client
    }

    #[tokio::test]
    async fn test_successful_event_handling() {
        let mut handler = setup_handler();

        handler
            .expect_handle()
            .times(2)
            .returning(|_, _| Ok(vec![]));

        let events = vec![Event::BlockBegin(1u32.into()), Event::BlockEnd(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .handler_retry_policy(RetryPolicy::NoRetry)
            .build();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            task.run(&mut client, CancellationToken::new()),
        )
        .await;

        assert!(result.is_ok());
        let task_result = result.unwrap();
        assert!(task_result.is_ok());
    }

    #[tokio::test]
    async fn test_handler_error_continues_processing() {
        let mut handler = setup_handler();

        handler
            .expect_handle()
            .times(1)
            .returning(|_, _| Err(report!(Error::HandlerFailed)));

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handler_error_with_continue() {
        let mut handler = setup_handler();

        handler.expect_handle().times(2).returning(|event, _| {
            let height = match event {
                Event::BlockBegin(h) => h.value(),
                _ => 0,
            };

            if height == 1 {
                Err(report!(Error::HandlerFailed))
            } else {
                Ok(vec![])
            }
        });

        let events = vec![
            Event::BlockBegin(1u32.into()),
            Event::BlockBegin(2u32.into()),
        ];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_retry_policy() {
        let mut handler = setup_handler();

        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        handler.expect_handle().times(3).returning(move |_, _| {
            let mut count = call_count_clone.lock().unwrap();
            *count += 1;

            if *count <= 2 {
                Err(report!(Error::HandlerFailed))
            } else {
                Ok(vec![])
            }
        });

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .handler_retry_policy(RetryPolicy::RepeatConstant {
                sleep: Duration::from_millis(10),
                max_attempts: 3,
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_client_error_continues_processing() {
        let mut handler = setup_handler();
        handler.expect_handle().times(0);

        let mut client = MockClient::new();
        client.expect_subscribe().times(1).returning(|_, _| {
            Ok(tokio_stream::iter(vec![Err(report!(ClientError::from(
                AppError::InvalidResponse
            )))]))
        });

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stream_timeout_cancellation() {
        let handler = setup_handler();

        let mut client = MockClient::new();
        client.expect_subscribe().times(1).returning(move |_, _| {
            let result_events: Vec<error_stack::Result<Event, ClientError>> = vec![];
            Ok(tokio_stream::iter(result_events))
        });

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(50),
            })
            .build();

        let token = CancellationToken::new();
        let token_clone = token.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            token_clone.cancel();
        });

        let result = task.run(&mut client, token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_events_processing() {
        let mut handler = setup_handler();

        let event_count = Arc::new(Mutex::new(0));
        let event_count_clone = event_count.clone();

        handler.expect_handle().times(5).returning(move |_, _| {
            let mut count = event_count_clone.lock().unwrap();
            *count += 1;
            Ok(vec![])
        });

        let events = vec![
            Event::BlockBegin(1u32.into()),
            Event::BlockEnd(1u32.into()),
            Event::BlockBegin(2u32.into()),
            Event::BlockEnd(2u32.into()),
            Event::BlockBegin(3u32.into()),
        ];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*event_count.lock().unwrap(), 5);
    }

    #[tokio::test]
    async fn test_successful_message_broadcast() {
        let mut handler = setup_handler();

        let test_msgs = vec![
            Any {
                type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                value: vec![1, 2, 3],
            },
            Any {
                type_url: "/cosmos.staking.v1beta1.MsgDelegate".to_string(),
                value: vec![4, 5, 6],
            },
        ];

        handler
            .expect_handle()
            .times(1)
            .returning(move |_, _| Ok(test_msgs.clone()));

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        client.expect_broadcast().times(2).returning(|_| {
            Ok(BroadcastClientResponse {
                tx_hash: "test_hash".to_string(),
                index: 0,
            })
        });

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_failure_continues_processing() {
        let mut handler = setup_handler();

        let test_msg = Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        };

        handler
            .expect_handle()
            .times(1)
            .returning(move |_, _| Ok(vec![test_msg.clone()]));

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        client.expect_broadcast().times(1).returning(|_| {
            Err(report!(crate::grpc::error::Error::from(
                AppError::InvalidResponse
            )))
        });

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_with_empty_messages() {
        let mut handler = setup_handler();

        handler
            .expect_handle()
            .times(1)
            .returning(|_, _| Ok(vec![]));

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        client.expect_broadcast().times(0);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;
        assert!(result.is_ok());
    }
}
