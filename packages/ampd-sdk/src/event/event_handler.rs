use std::time::Duration;

use async_trait::async_trait;
use cosmrs::Any;
use error_stack::Context;
use events::{AbciEventTypeFilter, Event};
use futures::stream::StreamExt;
use futures::{pin_mut, Future};
use mockall::automock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{sleep, timeout};
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

    #[error("failed to create handler event type from client event")]
    TryIntoEventHandlerType,

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

pub enum ActionOutcome<T> {
    Success(T),
    Continue,
    Abort(Error),
}

pub enum StreamStatus {
    Active(Event),
    Closed,
    TimedOut,
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
    event_subscribe_error_cb: fn(&client::Error) -> HandlerTaskAction,
    handler_error_cb: fn(&H::Event, H::Err) -> HandlerTaskAction,
    broadcaster_error_cb: fn(&Any, H::Err) -> HandlerTaskAction,
}

impl<H, C> HandlerTask<H, C>
where
    H: EventHandler,
    C: client::Client,
{
    pub async fn run(&mut self, token: CancellationToken) -> Result<(), Error> {
        let subscription_args = self.handler.subscribe_args().await;

        let event_stream = self
            .client
            .subscribe(
                subscription_args.event_filters,
                subscription_args.include_block_begin_end,
            )
            .await
            .map_err(|_e| Error::ClientEventStream)?;

        let child_token = token.child_token();
        let combined_stream = event_stream.take_until(child_token.cancelled());
        pin_mut!(combined_stream);

        loop {
            let stream_status =
                match timeout(self.config.stream_timeout, combined_stream.next()).await {
                    Err(_) => StreamStatus::TimedOut,
                    Ok(None) => StreamStatus::Closed,
                    Ok(Some(event_result)) => match event_result {
                        Ok(event) => {
                            let handler_event: H::Event = event
                                .clone()
                                .try_into()
                                .map_err(|_e| Error::TryIntoEventHandlerType)?;

                            match handle_error_action(
                                with_retry(
                                    || self.handler.handle(&handler_event, child_token.clone()),
                                    self.handler_retry_policy,
                                )
                                .await,
                                |err| (self.handler_error_cb)(&handler_event, err),
                                Error::HandlerFailed,
                            )
                            .await
                            {
                                ActionOutcome::Success(msgs) => {
                                    for msg in msgs {
                                        match handle_error_action(
                                            with_retry(
                                                || async { Ok(()) }, // Will be changed to broadcast later
                                                self.broadcast_retry_policy,
                                            )
                                            .await,
                                            |err| (self.broadcaster_error_cb)(&msg, err),
                                            Error::BroadcastFailed,
                                        )
                                        .await
                                        {
                                            ActionOutcome::Success(_) => {}
                                            ActionOutcome::Continue => break, // Skip to next item in loop
                                            ActionOutcome::Abort(err) => return Err(err),
                                        }
                                    }
                                    StreamStatus::Active(event)
                                }
                                ActionOutcome::Continue => continue,
                                ActionOutcome::Abort(err) => return Err(err),
                            }
                        }
                        Err(err) => match (self.event_subscribe_error_cb)(err.current_context()) {
                            HandlerTaskAction::Abort => return Err(Error::ClientEventStream),
                            HandlerTaskAction::Continue => continue,
                            HandlerTaskAction::ContinueAndSleep(duration) => {
                                sleep(duration).await;
                                continue;
                            }
                        },
                    },
                };

            if let StreamStatus::Active(Event::BlockBegin(height)) = &stream_status {
                info!(height = height.value(), "Handler started processing block");
            }
        }
    }
}

async fn handle_error_action<T, E>(
    result: Result<T, E>,
    error_callback: impl FnOnce(E) -> HandlerTaskAction,
    error_type: Error,
) -> ActionOutcome<T> {
    match result {
        Ok(value) => ActionOutcome::Success(value),
        Err(err) => {
            let action = error_callback(err);

            match action {
                HandlerTaskAction::Abort => ActionOutcome::Abort(error_type),
                HandlerTaskAction::Continue => ActionOutcome::Continue,
                HandlerTaskAction::ContinueAndSleep(duration) => {
                    sleep(duration).await;
                    ActionOutcome::Continue
                }
            }
        }
    }
}

// testing: mock client, mock event handler, .....
