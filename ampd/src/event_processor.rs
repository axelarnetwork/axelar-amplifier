use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use error_stack::{Context, Result, ResultExt};
use events::Event;
use futures::StreamExt;
use thiserror::Error;
use tokio::time::timeout;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use crate::asyncutil::task::TaskError;

use crate::handlers::chain;

#[async_trait]
pub trait EventHandler {
    type Err: Context;

    async fn handle(&self, event: &Event) -> Result<(), Self::Err>;

    fn chain<H>(self, handler: H) -> chain::Handler<Self, H>
    where
        Self: Sized,
        H: EventHandler,
    {
        chain::Handler::new(self, handler)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to process event")]
    Handler,
    #[error("could not consume events from stream")]
    EventStream,
    #[error("handler stopped prematurely")]
    Tasks(#[from] TaskError),
}

/// Let the `handler` consume events from the `event_stream`. The token is checked for cancellation
/// at the end of each consumed block or when the `event_stream` times out. If the token is cancelled or the
/// `event_stream` is closed, the function returns
pub async fn consume_events<H, S, E>(
    handler: H,
    event_stream: S,
    stream_timeout: Duration,
    token: CancellationToken,
) -> Result<(), Error>
where
    H: EventHandler,
    S: Stream<Item = Result<Event, E>>,
    E: Context,
{
    let mut event_stream = Box::pin(event_stream);
    loop {
        let stream_status = retrieve_next_event(&mut event_stream, stream_timeout)
            .await
            .change_context(Error::EventStream)?;

        if let StreamStatus::Active(event) = &stream_status {
            handler.handle(event).await.change_context(Error::Handler)?;
        }

        if should_task_stop(stream_status, &token) {
            return Ok(());
        }
    }
}

async fn retrieve_next_event<S, E>(
    event_stream: &mut Pin<Box<S>>,
    stream_timeout: Duration,
) -> Result<StreamStatus, E>
where
    S: Stream<Item = Result<Event, E>>,
    E: Context,
{
    let status = match timeout(stream_timeout, event_stream.next()).await {
        Err(_) => StreamStatus::TimedOut,
        Ok(None) => StreamStatus::Closed,
        Ok(Some(event)) => StreamStatus::Active(event?),
    };
    Ok(status)
}

fn should_task_stop(stream_status: StreamStatus, token: &CancellationToken) -> bool {
    match stream_status {
        StreamStatus::Active(Event::BlockEnd(_)) | StreamStatus::TimedOut
            if token.is_cancelled() =>
        {
            true
        }
        StreamStatus::Closed => true,
        _ => false,
    }
}

enum StreamStatus {
    Active(Event),
    Closed,
    TimedOut,
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{consume_events, Error, EventHandler};
    use async_trait::async_trait;
    use error_stack::{report, Result};
    use futures::stream;
    use mockall::mock;
    use std::time::Duration;

    use crate::event_processor;
    use events::Event;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn stop_when_stream_closes() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(events.len())
            .returning(|_| Ok(()));

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                stream::iter(events),
                Duration::from_secs(1000),
                CancellationToken::new(),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test]
    async fn return_error_when_stream_fails() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Err(report!(Error::EventStream)),
        ];

        let mut handler = MockEventHandler::new();
        handler.expect_handle().times(1).returning(|_| Ok(()));

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                stream::iter(events),
                Duration::from_secs(1000),
                CancellationToken::new(),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_err());
    }

    #[tokio::test]
    async fn return_error_when_handler_fails() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockEnd(0_u32.into())),
            Ok(Event::BlockEnd(1_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .times(1)
            .returning(|_| Err(report!(EventHandlerError::Failed)));

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                stream::iter(events),
                Duration::from_secs(1000),
                CancellationToken::new(),
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_err());
    }

    #[tokio::test]
    async fn react_to_cancellation_at_block_end() {
        let events: Vec<Result<Event, event_processor::Error>> = vec![
            Ok(Event::BlockBegin(0_u32.into())),
            Ok(Event::BlockBegin(1_u32.into())),
            Ok(Event::BlockBegin(2_u32.into())),
            Ok(Event::BlockEnd(3_u32.into())),
            Ok(Event::BlockBegin(4_u32.into())),
        ];

        let mut handler = MockEventHandler::new();
        handler.expect_handle().times(4).returning(|_| Ok(()));

        let token = CancellationToken::new();
        token.cancel();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                stream::iter(events),
                Duration::from_secs(1000),
                token,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[tokio::test]
    async fn react_to_cancellation_on_timeout() {
        let mut handler = MockEventHandler::new();
        handler.expect_handle().times(0).returning(|_| Ok(()));

        let token = CancellationToken::new();
        token.cancel();

        let result_with_timeout = timeout(
            Duration::from_secs(1),
            consume_events(
                handler,
                stream::pending::<Result<Event, Error>>(), // never returns any items so it can time out
                Duration::from_secs(0),
                token,
            ),
        )
        .await;

        assert!(result_with_timeout.is_ok());
        assert!(result_with_timeout.unwrap().is_ok());
    }

    #[derive(Error, Debug)]
    pub enum EventHandlerError {
        #[error("failed")]
        Failed,
    }

    mock! {
            EventHandler{}

            #[async_trait]
            impl EventHandler for EventHandler {
                type Err = EventHandlerError;

                async fn handle(&self, event: &Event) -> Result<(), EventHandlerError>;
            }
    }
}
