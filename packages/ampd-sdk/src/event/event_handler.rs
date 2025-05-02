use std::fmt::Display;
use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{report, Context, Report, ResultExt};
use events::{AbciEventTypeFilter, Event};
use futures::{pin_mut, Stream, TryFutureExt};
use mockall::automock;
use report::ErrorExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::interval;
use tokio_stream::{Elapsed, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use typed_builder::TypedBuilder;

use crate::event::callbacks::{
    default_broadcast_error_cb, default_event_subscription_error_cb, default_handler_error_cb,
};
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
        token: &CancellationToken,
    ) -> Result<Vec<Any>, Self::Err>;

    fn subscription_params(&self) -> SubscriptionParams;
}

pub struct SubscriptionParams {
    event_filters: Vec<AbciEventTypeFilter>,
    include_block_begin_end: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[allow(dead_code)]
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

    #[error("{0} task aborted")]
    TaskAborted(String),
}

#[allow(dead_code)]
pub enum HandlerTaskAction {
    Abort,
    Continue,
    ContinueAndSleep(Duration),
}

#[derive(TypedBuilder)]
#[allow(dead_code)]
pub struct HandlerTask<H>
where
    H: EventHandler,
    <H::Event as TryFrom<Event>>::Error: Context,
    H::Event: Display,
{
    handler: H,
    config: Config,
    #[builder(default = String::from("default_task"))]
    task_label: String,
    #[builder(default = RetryPolicy::NoRetry)]
    handler_retry_policy: RetryPolicy,
    #[builder(default = RetryPolicy::NoRetry)]
    broadcast_retry_policy: RetryPolicy,
    #[builder(default = default_event_subscription_error_cb)]
    event_subscription_error_cb: fn(Report<Error>) -> HandlerTaskAction,
    #[builder(default = default_handler_error_cb)]
    handler_error_cb: fn(&H::Event, H::Err) -> HandlerTaskAction,
    #[builder(default = default_broadcast_error_cb)]
    broadcast_error_cb: fn(&[Any], H::Err) -> HandlerTaskAction,
}

#[allow(dead_code)]
impl<H> HandlerTask<H>
where
    H: EventHandler,
    <H::Event as TryFrom<Event>>::Error: Context,
    H::Event: Display,
{
    pub async fn run(
        self,
        client: &mut impl client::Client,
        token: CancellationToken,
    ) -> error_stack::Result<(), Error> {
        let task_label = self.task_label.clone();
        let stream = self
            .subscribe_to_stream(client, &token)
            .await?
            .then(|element| self.process_stream(element, &token));

        pin_mut!(stream);
        while let Some(action) = stream.next().await {
            match action {
                HandlerTaskAction::Continue => continue,
                HandlerTaskAction::ContinueAndSleep(timeout) => tokio::time::sleep(timeout).await,
                HandlerTaskAction::Abort => return Err(report!(Error::TaskAborted(task_label))),
            }
        }

        Ok(())
    }

    async fn subscribe_to_stream<'a>(
        &self,
        client: &'a mut impl client::Client,
        token: &'a CancellationToken,
    ) -> error_stack::Result<impl Stream<Item = error_stack::Result<Event, Error>> + 'a, Error>
    {
        let subscription_params = self.handler.subscription_params();

        let stream = client
            .subscribe(
                subscription_params.event_filters,
                subscription_params.include_block_begin_end,
            )
            .await
            .change_context(Error::EventStream)?
            .take_while(|_| !token.is_cancelled())
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
        token: &CancellationToken,
    ) -> HandlerTaskAction {
        let action = self
            .parse_event(element)
            .and_then(|event| self.handle_event(event, token))
            .and_then(|msgs| self.broadcast_msgs(msgs, token))
            .await
            .map(|_| HandlerTaskAction::Continue);

        action.unwrap_or_else(|err_action| err_action)
    }

    async fn parse_event(
        &self,
        element: error_stack::Result<Event, Error>,
    ) -> Result<H::Event, HandlerTaskAction> {
        element
            .inspect(Self::log_block_boundary)
            .and_then(|event| {
                H::Event::try_from(event.clone())
                    .change_context(Error::EventConversion)
                    .attach_printable(format!("failed to create handler event from: {event}"))
            })
            .map_err(self.event_subscription_error_cb)
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

    async fn handle_event(
        &self,
        event: H::Event,
        token: &CancellationToken,
    ) -> Result<Vec<Any>, HandlerTaskAction> {
        with_retry(
            || self.handler.handle(&event, token),
            self.handler_retry_policy,
        )
        .await
        .map_err(|err| (self.handler_error_cb)(&event, err))
    }

    async fn broadcast_msgs(
        &self,
        msgs: Vec<Any>,
        _token: &CancellationToken,
    ) -> Result<(), HandlerTaskAction> {
        with_retry(|| async { Ok(()) }, self.broadcast_retry_policy) // Placeholder for actual broadcast
            .await
            .map_err(|err| (self.broadcast_error_cb)(&msgs, err))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::grpc::client::{Error as ClientError, MockClient};

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
            .broadcast_retry_policy(RetryPolicy::NoRetry)
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
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
    async fn test_handler_error_with_abort() {
        let mut handler = setup_handler();

        handler
            .expect_handle()
            .times(1)
            .returning(|_, _| Err(Error::HandlerFailed));

        let events = vec![Event::BlockBegin(1u32.into())];
        let mut client = mock_client_subscribe_with_events(events);

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::TaskAborted(_)
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
                Err(Error::HandlerFailed)
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
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Continue)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
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
                Err(Error::HandlerFailed)
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
            .broadcast_retry_policy(RetryPolicy::NoRetry)
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_client_error() {
        let mut handler = setup_handler();
        handler.expect_handle().times(0);

        let mut client = MockClient::new();
        client.expect_subscribe().times(1).returning(move |_, _| {
            let result_events: Vec<error_stack::Result<Event, ClientError>> =
                vec![Err(report!(ClientError::InvalidResponse))];
            Ok(tokio_stream::iter(result_events))
        });

        let task = HandlerTask::builder()
            .handler(handler)
            .config(Config {
                stream_timeout: Duration::from_millis(100),
            })
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::TaskAborted(_)
        ));
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
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
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
            .event_subscription_error_cb(|_| HandlerTaskAction::Abort)
            .handler_error_cb(|_, _| HandlerTaskAction::Abort)
            .broadcast_error_cb(|_, _| HandlerTaskAction::Abort)
            .build();

        let result = task.run(&mut client, CancellationToken::new()).await;

        assert!(result.is_ok());
        assert_eq!(*event_count.lock().unwrap(), 5);
    }

    #[tokio::test]
    #[ignore = "Broadcast functionality not yet implemented"]
    async fn test_broadcast_message_failure() {
        // This will be skipped until the broadcast functionality is implemented
    }
}
