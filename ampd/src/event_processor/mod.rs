mod consume;

use std::time::Duration;
use std::vec;

use async_trait::async_trait;
use axelar_wasm_std::error::extend_err;
use error_stack::{Context, Result, ResultExt};
use events::Event;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::asyncutil::task::{CancellableTask, Task};
use crate::event_processor::consume::consume_events;

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
    Tasks,
}

/// The EventProcessor is responsible for the management of handlers that consume events from event streams.
/// It cancels all handlers if one of them fails, and returns all errors that occurred during processing.
pub struct EventProcessor {
    tasks: Vec<CancellableTask<Result<(), Error>>>,
}

impl EventProcessor {
    pub fn new() -> Self {
        EventProcessor { tasks: vec![] }
    }

    /// Creates and manages a task in which the handler consumes events from the event stream.
    /// Handlers try to shut down gracefully at the end of the current block if the tasks gets cancelled.
    /// In case the event stream blocks, the event processor checks after `stream_timeout` if the task should be cancelled.
    pub fn add_handler<H, S, E>(
        &mut self,
        handler: H,
        event_stream: S,
        stream_timeout: Duration,
    ) -> &mut Self
    where
        H: EventHandler + Send + 'static,
        S: Stream<Item = Result<Event, E>> + Send + 'static,
        E: Context,
    {
        self.tasks.push(CancellableTask::create(move |token| {
            consume_events(handler, event_stream, stream_timeout, token)
        }));
        self
    }

    /// Runs all handler tasks until one of them fails or the cancellation token is triggered,
    /// at which time all tasks receive the signal to be cancelled.
    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let mut running_tasks = start_tasks(self.tasks, token.clone());
        wait_for_completion(&mut running_tasks, &token).await
    }
}

fn start_tasks(
    tasks: Vec<CancellableTask<Result<(), Error>>>,
    token: CancellationToken,
) -> JoinSet<Result<(), Error>> {
    let mut join_set = JoinSet::new();

    for task in tasks.into_iter() {
        // tasks clean up on their own after the cancellation token is triggered, so we discard the abort handles
        join_set.spawn(task(token.clone()));
    }
    join_set
}

async fn wait_for_completion(
    running_tasks: &mut JoinSet<Result<(), Error>>,
    token: &CancellationToken,
) -> Result<(), Error> {
    let mut final_result = Ok(());
    let total_task_count = running_tasks.len();
    while let Some(task_result) = running_tasks.join_next().await {
        // if one task stops, all others should stop as well, so we cancel the token.
        // Any call to this after the first is a no-op, so no need to guard it.
        token.cancel();
        info!(
            "shutting down event handlers ({}/{})...",
            running_tasks.len(),
            total_task_count
        );

        final_result = match task_result.change_context(Error::Tasks) {
            Err(err) | Ok(Err(err)) => extend_err(final_result, err),
            Ok(_) => final_result,
        };
    }

    final_result
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{EventHandler, EventProcessor};
    use async_trait::async_trait;
    use error_stack::{Report, Result};
    use futures::TryStreamExt;
    use mockall::mock;
    use std::thread::sleep;
    use std::time::Duration;

    use thiserror::Error;

    use tokio::{self, sync::broadcast};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn processor_returns_immediately_when_no_handlers_are_added() {
        let processor = EventProcessor::new();
        assert!(processor.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn should_handle_events() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::new();

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Ok(()))
            // make sure the handler is called for each event
            .times(event_count);

        processor.add_handler(
            handler,
            BroadcastStream::new(rx).map_err(Report::from),
            Duration::from_secs(1),
        );

        tokio::spawn(async move {
            for i in 0..event_count {
                tx.send(events::Event::BlockEnd((i as u32).into()))
                    .expect("sending events should not fail");
            }
        });

        assert!(processor.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn should_return_error_if_handler_fails() {
        let (tx, rx) = broadcast::channel::<events::Event>(10);
        let mut processor = EventProcessor::new();

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Err(EventHandlerError::Unknown.into()))
            .once();

        processor.add_handler(
            handler,
            BroadcastStream::new(rx).map_err(Report::from),
            Duration::from_secs(1),
        );

        tokio::spawn(async move {
            tx.send(events::Event::BlockEnd((10_u32).into()))
                .expect("sending events should not fail");
        });

        assert!(processor.run(CancellationToken::new()).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panic_in_one_handler_should_stop_all() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::new();

        let mut handler2 = MockEventHandler::new();
        handler2
            .expect_handle()
            .returning(move |event| {
                panic!("some unexpected failure");
                Ok(())
            })
            .times(event_count);

        let mut handler1 = MockEventHandler::new();
        handler1.expect_handle().returning(|_| {
            sleep(Duration::from_secs(1));
            return Ok(());
        });

        processor
            .add_handler(
                handler2,
                BroadcastStream::new(tx.subscribe()).map_err(Report::from),
                Duration::from_secs(1),
            )
            .add_handler(
                handler1,
                BroadcastStream::new(rx).map_err(Report::from),
                Duration::from_secs(1),
            );

        for i in 0..event_count {
            tx.send(events::Event::BlockEnd((i as u32).into()))
                .expect("sending events should not fail");
        }

        assert!(processor.run(CancellationToken::new()).await.is_err());

        // ensure tx lives until after processor returns so we can be sure that it stopped prematurely
        drop(tx);
    }

    #[tokio::test]
    async fn should_support_multiple_types_of_handlers() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::new();

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Ok(()))
            .times(event_count);

        let mut another_handler = MockAnotherEventHandler::new();
        another_handler
            .expect_handle()
            .returning(|_| Ok(()))
            .times(event_count);

        processor
            .add_handler(
                handler,
                BroadcastStream::new(rx).map_err(Report::from),
                Duration::from_secs(1),
            )
            .add_handler(
                another_handler,
                BroadcastStream::new(tx.subscribe()).map_err(Report::from),
                Duration::from_secs(1),
            );

        tokio::spawn(async move {
            for i in 0..event_count {
                tx.send(events::Event::BlockEnd((i as u32).into()))
                    .expect("sending events should not fail");
            }
        });

        assert!(processor.run(CancellationToken::new()).await.is_ok());
    }

    #[derive(Error, Debug)]
    pub enum EventHandlerError {
        #[error("unknown")]
        Unknown,
    }

    mock! {
            EventHandler{}

            #[async_trait]
            impl EventHandler for EventHandler {
                type Err = EventHandlerError;

                async fn handle(&self, event: &events::Event) -> Result<(), EventHandlerError>;
            }
    }

    #[derive(Error, Debug)]
    pub enum AnotherEventHandlerError {}

    mock! {
            AnotherEventHandler{}

            #[async_trait]
            impl EventHandler for AnotherEventHandler {
                type Err = AnotherEventHandlerError;

                async fn handle(&self, event: &events::Event) -> Result<(), AnotherEventHandlerError>;
            }
    }
}
