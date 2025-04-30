use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{report, Context, Report, Result, ResultExt};
use events::{AbciEventTypeFilter, Event};
use futures::{pin_mut, TryStreamExt};
use mockall::automock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{interval, sleep};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::info;
use typed_builder::TypedBuilder;

use crate::grpc::client;
use crate::utils::{with_retry, RetryPolicy};

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
    ) -> Result<Vec<Any>, Self::Err>;

    async fn subscribe_args(&self) -> SubscribeArgs;
}

pub struct SubscribeArgs {
    pub event_filters: Vec<AbciEventTypeFilter>,
    pub include_block_begin_end: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(with = "humantime_serde")]
    pub stream_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stream_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to retreive events stream from the client")]
    ClientEventStream,

    #[error("timeout while waiting for event stream")]
    StreamTimeout,

    #[error("unable to parse event of type")] // attach printable
    EventConversion,

    #[error("error when handling event messages")]
    HandlerFailed,

    #[error("error when broadcasting message")]
    BroadcastFailed,
}

pub enum HandlerTaskAction {
    Abort,
    Continue,
    ContinueAndSleep(Duration),
}

enum ActionOutcome<T> {
    Success(T),
    HandlerAction(HandlerTaskAction, Error),
}

#[derive(TypedBuilder)]
#[allow(dead_code)]
pub struct HandlerTask<H, C>
where
    H: EventHandler,
    C: client::Client,
{
    handler: H,
    client: C,
    config: Config,
    #[builder(default = RetryPolicy::NoRetry)]
    handler_retry_policy: RetryPolicy,
    #[builder(default = RetryPolicy::NoRetry)]
    broadcast_retry_policy: RetryPolicy,
    event_subscribe_error_cb: fn(Report<client::Error>) -> HandlerTaskAction,
    handler_error_cb: fn(&H::Event, &H::Err) -> HandlerTaskAction,
    broadcaster_error_cb: fn(&Any, H::Err) -> HandlerTaskAction,
}

impl<H, C> HandlerTask<H, C>
where
    H: EventHandler,
    C: client::Client,
{
    fn log_block_start_and_end(event: &Event) {
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

    pub async fn run(&mut self, token: CancellationToken) -> Result<(), Error> {
        let subscription_args = self.handler.subscribe_args().await;

        let event_stream = self
            .client
            .subscribe(
                subscription_args.event_filters,
                subscription_args.include_block_begin_end,
            )
            .await
            .change_context(Error::ClientEventStream)?;

        let child_token = token.child_token();

        let intermediate_stream = event_stream
            .take_while(|_| !child_token.is_cancelled())
            .timeout_repeating(interval(self.config.stream_timeout))
            .map(|element| element.change_context(Error::StreamTimeout).and_then(
                |event| event.change_context(Error::ClientEventStream)
                .inspect(HandlerTask::log_block_start_and_end)
                .and_then(|event| {
                    H::Event::try_from(event).map_err(|_| report!(Error::EventConversion))
                })
            ));
            // .and_then(|event| {
            //     H::Event::try_from(event).map_err(|_| report!(Error::EventConversion))
            // });

        let processed_stream = intermediate_stream.then(|handler_event_result| async {
            match handler_event_result {
                Ok(handler_event) => {
                    let handle_result = with_retry(
                        || self.handler.handle(&handler_event, child_token.clone()),
                        self.handler_retry_policy,
                    )
                    .await;

                    match handle_result {
                        Ok(msgs) => {
                            for msg in msgs {
                                let broadcast_result = with_retry(
                                    || async { Ok(()) }, // Placeholder for actual broadcast
                                    self.broadcast_retry_policy,
                                )
                                .await;

                                if let Err(err) = broadcast_result {
                                    return Ok(ActionOutcome::HandlerAction(
                                        (self.broadcaster_error_cb)(&msg, err),
                                        Error::BroadcastFailed,
                                    ));
                                }
                            }
                            Ok(ActionOutcome::Success(()))
                        }
                        Err(err) => Ok(ActionOutcome::HandlerAction(
                            (self.handler_error_cb)(&handler_event, err.current_context()),
                            Error::HandlerFailed,
                        )),
                    }
                }
                Err(client_err) => {
                    Ok(ActionOutcome::HandlerAction(
                        (self.event_subscribe_error_cb)(client_err),
                        Error::ClientEventStream,
                    ))
                }
            }
        });

        pin_mut!(processed_stream);
        while let Some(result) = processed_stream.next().await {
            match result {
                Ok(ActionOutcome::Success(_)) => {
                    continue; // Successfully processed the event
                }
                Ok(ActionOutcome::HandlerAction(action, error)) => {
                    match action {
                        HandlerTaskAction::Abort => {
                            return Err(report!(error));
                        }
                        HandlerTaskAction::Continue => {
                            continue; // Continue processing the next event
                        }
                        HandlerTaskAction::ContinueAndSleep(duration) => {
                            sleep(duration).await;
                        }
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::grpc::client::{Error as ClientError, MockClient};

    fn setup_handler() -> MockEventHandler {
        let mut handler = MockEventHandler::new();
        handler.expect_subscribe_args().returning(|| SubscribeArgs {
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
                let result_events: Vec<Result<Event, ClientError>> =
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
        let client = mock_client_subscribe_with_events(events);

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .handler_retry_policy(RetryPolicy::NoRetry)
            .broadcast_retry_policy(RetryPolicy::NoRetry)
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result =
            tokio::time::timeout(Duration::from_secs(1), task.run(CancellationToken::new())).await;

        assert!(result.is_ok());
        let task_result = result.unwrap();
        assert!(task_result.is_ok());
    }

    #[tokio::test]
    async fn test_handler_error_with_abort() {
        let mut handler = setup_handler();

        handler
            .expect_handle()
            .times(1)
            .returning(|_, _| Err(report!(Error::HandlerFailed)));

        let events = vec![Event::BlockBegin(1u32.into())];
        let client = mock_client_subscribe_with_events(events);

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(CancellationToken::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::HandlerFailed
        ));
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
        let client = mock_client_subscribe_with_events(events);

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Continue)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(CancellationToken::new()).await;
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
                Err(Report::new(Error::HandlerFailed))
            } else {
                Ok(vec![])
            }
        });

        let events = vec![Event::BlockBegin(1u32.into())];
        let client = mock_client_subscribe_with_events(events);

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .handler_retry_policy(RetryPolicy::RepeatConstant {
                sleep: Duration::from_millis(10),
                max_attempts: 3,
            })
            .broadcast_retry_policy(RetryPolicy::NoRetry)
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_client_error() {
        let mut handler = setup_handler();
        handler.expect_handle().times(0);

        let mut client = MockClient::new();
        client.expect_subscribe().times(1).returning(move |_, _| {
            let result_events: Vec<Result<Event, ClientError>> =
                vec![Err(report!(ClientError::InvalidResponse))];
            Ok(tokio_stream::iter(result_events))
        });

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(CancellationToken::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::ClientEventStream
        ));
    }

    #[tokio::test]
    async fn test_stream_timeout_cancellation() {
        let handler = setup_handler();

        let mut client = MockClient::new();
        client.expect_subscribe().times(1).returning(move |_, _| {
            let result_events: Vec<Result<Event, ClientError>> = vec![];
            Ok(tokio_stream::iter(result_events))
        });

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(50),
            })
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let token = CancellationToken::new();
        let token_clone = token.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            token_clone.cancel();
        });

        let result = task.run(token).await;
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
        let client = mock_client_subscribe_with_events(events);

        let mut task = HandlerTask::builder()
            .handler(handler)
            .client(client)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscribe_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcaster_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*event_count.lock().unwrap(), 5);
    }

    #[tokio::test]
    #[ignore = "Broadcast functionality not yet implemented"]
    async fn test_broadcast_message_failure() {
        // This will be skipped until the broadcast functionality is implemented
    }
}
