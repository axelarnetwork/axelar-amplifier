mod consume;

use std::time::Duration;

use async_trait::async_trait;
use error_stack::{Context, Result};
use events::Event;
use thiserror::Error;
use tokio_stream::Stream;

use crate::asyncutil::task::{CancellableTask, Task, TaskError};
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

impl From<TaskError> for Error {
    fn from(_err: TaskError) -> Self {
        Error::Tasks
    }
}

pub fn create_event_stream_task<H, S, E>(
    handler: H,
    event_stream: S,
    stream_timeout: Duration,
) -> CancellableTask<Result<(), Error>>
where
    H: EventHandler + Send + 'static,
    S: Stream<Item = Result<Event, E>> + Send + 'static,
    E: Context,
{
    CancellableTask::create(move |token| {
        consume_events(handler, event_stream, stream_timeout, token)
    })
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{EventHandler, TaskManager};
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
        let processor = TaskManager::new();
        assert!(processor.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn should_handle_events() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = TaskManager::new();

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Ok(()))
            // make sure the handler is called for each event
            .times(event_count);

        processor.add_task(
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
        let mut processor = TaskManager::new();

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Err(EventHandlerError::Unknown.into()))
            .once();

        processor.add_task(
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
        let mut processor = TaskManager::new();

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
            .add_task(
                handler2,
                BroadcastStream::new(tx.subscribe()).map_err(Report::from),
                Duration::from_secs(1),
            )
            .add_task(
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
        let mut processor = TaskManager::new();

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
            .add_task(
                handler,
                BroadcastStream::new(rx).map_err(Report::from),
                Duration::from_secs(1),
            )
            .add_task(
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
