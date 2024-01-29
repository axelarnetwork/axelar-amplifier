use crate::event_processor::{Error, EventHandler};
use error_stack::{Context, ResultExt};
use events::Event;
use futures::Stream;
use futures::StreamExt;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Let the `handler` consume events from the `event_stream`. The token is checked for cancellation
/// at the end of each consumed block or when the `event_stream` times out. If the token is cancelled or the
/// `event_stream` is closed, the function returns
pub async fn consume_events<H, S, E>(
    handler: H,
    event_stream: S,
    stream_timeout: Duration,
    token: CancellationToken,
) -> error_stack::Result<(), Error>
where
    H: EventHandler,
    S: Stream<Item = error_stack::Result<Event, E>>,
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
) -> error_stack::Result<StreamStatus, E>
where
    S: Stream<Item = error_stack::Result<Event, E>>,
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
