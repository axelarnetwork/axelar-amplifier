use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::Context;
use events::{AbciEventTypeFilter, Event};
use futures::stream::StreamExt;
use futures::{pin_mut, Future};
// use mockall::automock;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::info;
use typed_builder::TypedBuilder;

use crate::grpc::client;

#[async_trait]
pub trait EventHandler: Send + Sync {
    type Err: Context;
    type Event: TryFrom<Event>;

    async fn handle(&self, event: &Self::Event) -> Result<Vec<Any>, Self::Err>;

    async fn client_filters(&self) -> Vec<AbciEventTypeFilter>;

    async fn include_block_begin_end(&self) -> bool;

    fn set_config(&mut self, config: Config);

    fn config(&self) -> &Config;

    // async fn handle_event_subscribe_error(&self, err: grpc::Error) -> HandlerTaskAction {
    //     warn!(
    //         err = LoggableError::from(&err).as_value(),
    //         "failed to receive event"
    //     );

    //     HandlerTaskAction::Continue
    // }

    // async fn handle_handler_error(&self, event: &Self::Event, err: Self::Err) -> HandlerTaskAction {
    //     warn!(
    //         err = LoggableError::from(&err).as_value(),
    //         event = event.to_string(),
    //         "handler failed to process event"
    //     );

    //     HandlerTaskAction::Continue
    // }

    // async fn handle_broadcaster_error(&self, msg: Any, err: grpc::Error) -> HandlerTaskAction {
    //     warn!(
    //         err = LoggableError::from(&err).as_value(),
    //         msg = msg.to_string(),
    //         "failed to broadcast message"
    //     );

    //     HandlerTaskAction::Continue
    // }
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
    #[error("failed to retreive events from the client stream")]
    ClientEventStream,

    #[error("failed to create handler event from event")]
    TryFromEvent,

    #[error("error when handling event messages and task action is set to abort")]
    HandlerFailed,

    #[error("error when broadcasting message and task action is set to abort")]
    BroadcastFailed,
}

pub enum HandlerTaskAction {
    Abort,
    Continue,
    ContinueAndSleep(Duration),
}

#[derive(Copy, Clone)]
pub enum RetryPolicy {
    RepeatConstant { sleep: Duration, max_attempts: u64 },
    NoRetry,
}

impl RetryPolicy {
    fn max_attempts(&self) -> u64 {
        match self {
            RetryPolicy::RepeatConstant { max_attempts, .. } => *max_attempts,
            RetryPolicy::NoRetry => 1,
        }
    }

    fn delay(&self) -> Option<Duration> {
        match self {
            RetryPolicy::RepeatConstant { sleep, .. } => Some(*sleep),
            RetryPolicy::NoRetry => None,
        }
    }
}

pub enum StreamStatus {
    Active(Event),
    Closed,
    TimedOut,
}

#[derive(TypedBuilder)]
#[allow(dead_code)]
pub struct HandlerTask<H>
where
    H: EventHandler,
{
    handler: H,
    client: client::GrpcClient,
    #[builder(default = RetryPolicy::NoRetry)]
    handler_retry_policy: RetryPolicy,
    #[builder(default = RetryPolicy::NoRetry)]
    broadcast_retry_policy: RetryPolicy,
    event_subscribe_error_cb: fn(client::Error) -> HandlerTaskAction,
    handler_error_cb: fn(&H::Event, H::Err) -> HandlerTaskAction,
    broadcaster_error_cb: fn(&Any, H::Err) -> HandlerTaskAction,
}

impl<H> HandlerTask<H>
where
    H: EventHandler,
{
    pub async fn run(&mut self, token: CancellationToken) -> Result<(), Error> {
        let event_stream = <client::GrpcClient as client::Client>::subscribe(
            &mut self.client,
            self.handler.client_filters().await,
            self.handler.include_block_begin_end().await,
        )
        .await
        .map_err(|_| Error::ClientEventStream)?;

        let combined_stream = event_stream.take_until(token.cancelled());
        pin_mut!(combined_stream);

        loop {
            let stream_status =
                match timeout(self.handler.config().stream_timeout, combined_stream.next()).await {
                    Err(_) => StreamStatus::TimedOut,
                    Ok(None) => StreamStatus::Closed,
                    Ok(Some(event_result)) => match event_result {
                        Ok(event) => StreamStatus::Active(event),
                        Err(err) => {
                            let action = (self.event_subscribe_error_cb)(*err.current_context());

                            match action {
                                HandlerTaskAction::Abort => return Err(Error::ClientEventStream),
                                HandlerTaskAction::Continue => continue,
                                HandlerTaskAction::ContinueAndSleep(duration) => {
                                    sleep(duration).await;
                                    continue;
                                }
                            }
                        }
                    },
                };

            if let StreamStatus::Active(event) = &stream_status {
                let handler_event = <H::Event as TryFrom<Event>>::try_from(event.clone())
                    .map_err(|_| Error::TryFromEvent)?;

                let msgs = match with_retry(
                    || self.handler.handle(&handler_event),
                    self.handler_retry_policy,
                )
                .await
                {
                    Ok(msgs) => msgs,
                    Err(err) => {
                        let action = (self.handler_error_cb)(&handler_event, err);

                        match action {
                            HandlerTaskAction::Abort => return Err(Error::HandlerFailed),
                            HandlerTaskAction::Continue => continue,
                            HandlerTaskAction::ContinueAndSleep(duration) => {
                                tokio::time::sleep(duration).await;
                                continue;
                            }
                        }
                    }
                };

                for msg in msgs {
                    let broadcast_result = with_retry(
                        || async { Ok(()) }, // This will later be replace with self.client.broadcast(msg.clone())
                        self.broadcast_retry_policy,
                    )
                    .await;

                    if let Err(err) = broadcast_result {
                        let action = (self.broadcaster_error_cb)(&msg, err);

                        match action {
                            HandlerTaskAction::Abort => return Err(Error::BroadcastFailed),
                            HandlerTaskAction::Continue => continue,
                            HandlerTaskAction::ContinueAndSleep(duration) => {
                                tokio::time::sleep(duration).await;
                                continue;
                            }
                        }
                    }
                }

                if let Event::BlockEnd(height) = &event {
                    info!(height = height.value(), "Handler finished processing block");
                }
            }
        }
    }
}

pub async fn with_retry<F, Fut, R, Err>(mut future: F, policy: RetryPolicy) -> Result<R, Err>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    let mut attempts = 0;

    loop {
        match future().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                attempts += 1;

                if attempts >= policy.max_attempts() {
                    return Err(err);
                }

                if let Some(delay) = policy.delay() {
                    sleep(delay).await;
                }
            }
        }
    }
}
