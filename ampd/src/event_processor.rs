use core::future::Future;
use core::pin::Pin;
use std::vec;

use async_trait::async_trait;
use error_stack::{Context, Report, Result, ResultExt};
use events::Event;
use futures::StreamExt;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use crate::handlers::chain;

type Task = Box<dyn Future<Output = Result<(), Error>> + Send>;

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

pub struct EventProcessor {
    tasks: Vec<Pin<Task>>,
    token: CancellationToken,
}

impl EventProcessor {
    pub fn with_cancel(token: CancellationToken) -> Self {
        EventProcessor {
            tasks: vec![],
            token,
        }
    }

    pub fn add_handler<H, S, E>(&mut self, handler: H, event_stream: S) -> &mut Self
    where
        H: EventHandler + Send + 'static,
        S: Stream<Item = Result<Event, E>> + Send + 'static,
        E: Context,
    {
        self.tasks.push(Box::pin(EventProcessor::consume_events(
            event_stream,
            handler,
            self.token.child_token(),
        )));
        self
    }

    pub async fn run(self) -> Result<(), Error> {
        let mut join_set = JoinSet::new();

        for task in self.tasks.into_iter() {
            // tasks clean up on their own after the cancellation token is triggered, so we discard the abort handles
            join_set.spawn(task);
        }

        EventProcessor::wait_for_completion(&mut join_set, &self.token).await
    }

    async fn consume_events<H, S, E>(
        event_stream: S,
        handler: H,
        token: CancellationToken,
    ) -> Result<(), Error>
    where
        H: EventHandler,
        S: Stream<Item = Result<Event, E>>,
        E: Context,
    {
        let mut event_stream = Box::pin(event_stream);
        while let Some(event) = event_stream.next().await {
            let event = event.change_context(Error::EventStream)?;

            handler
                .handle(&event)
                .await
                .change_context(Error::Handler)?;

            if matches!(event, Event::BlockEnd(_)) && token.is_cancelled() {
                break;
            }
        }

        Ok(())
    }

    async fn wait_for_completion(
        join_set: &mut JoinSet<Result<(), Error>>,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        let mut extended_error = None;
        while let Some(result) = join_set.join_next().await {
            token.cancel();

            extended_error = match result.change_context(Error::Tasks) {
                Err(err) | Ok(Err(err)) => EventProcessor::extend_err(extended_error, err),
                Ok(_) => extended_error,
            };
        }

        if let Some(error) = extended_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn extend_err(
        base_err: Option<Report<Error>>,
        added_error: Report<Error>,
    ) -> Option<Report<Error>> {
        if let Some(mut base_err) = base_err {
            base_err.extend_one(added_error);
            Some(base_err)
        } else {
            Some(added_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{EventHandler, EventProcessor};
    use async_trait::async_trait;
    use error_stack::{Report, Result};
    use futures::executor::block_on;
    use futures::StreamExt;
    use futures::TryStreamExt;
    use mockall::mock;
    use std::ops::Deref;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::sleep;
    use std::time::Duration;
    use thiserror::Error;
    use tokio::{self, sync::broadcast};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn processor_returns_immediately_when_no_handlers_are_added() {
        let processor = EventProcessor::with_cancel(CancellationToken::new());
        assert!(processor.run().await.is_ok());
    }

    #[tokio::test]
    async fn should_handle_events() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::with_cancel(CancellationToken::new());

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Ok(()))
            // make sure the handler is called for each event
            .times(event_count);

        processor.add_handler(handler, BroadcastStream::new(rx).map_err(Report::from));

        tokio::spawn(async move {
            for i in 0..event_count {
                tx.send(events::Event::BlockEnd((i as u32).into()))
                    .expect("sending events should not fail");
            }
        });

        assert!(processor.run().await.is_ok());
    }

    #[tokio::test]
    async fn should_return_error_if_handler_fails() {
        let (tx, rx) = broadcast::channel::<events::Event>(10);
        let mut processor = EventProcessor::with_cancel(CancellationToken::new());

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Err(EventHandlerError::Unknown.into()))
            .once();

        processor.add_handler(handler, BroadcastStream::new(rx).map_err(Report::from));

        tokio::spawn(async move {
            tx.send(events::Event::BlockEnd((10_u32).into()))
                .expect("sending events should not fail");
        });

        assert!(processor.run().await.is_err());
    }

    #[tokio::test]
    async fn panic_in_one_handler_should_stop_all() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::with_cancel(CancellationToken::new());

        let mut handler1 = MockEventHandler::new();
        handler1.expect_handle().returning(|_| {
            return Ok(());
        });

        let mut handler2 = MockEventHandler::new();
        handler2
            .expect_handle()
            .returning(move |event| {
                if let events::Event::BlockEnd(height) = event {
                    if *height == 5_u32.into() {
                        panic!("some unexpected failure");
                    }
                }
                Ok(())
            })
            .times(5);

        processor
            .add_handler(handler1, BroadcastStream::new(rx).map_err(Report::from))
            .add_handler(
                handler2,
                BroadcastStream::new(tx.subscribe()).map_err(Report::from),
            );

        for i in 0..event_count {
            tx.send(events::Event::BlockEnd((i as u32).into()))
                .expect("sending events should not fail");
        }

        assert!(processor.run().await.is_err());

        // ensure tx lives until after processor returns so we can be sure that it stopped prematurely
        drop(tx);
    }

    #[tokio::test]
    async fn should_support_multiple_types_of_handlers() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<events::Event>(event_count);
        let mut processor = EventProcessor::with_cancel(CancellationToken::new());

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
            .add_handler(handler, BroadcastStream::new(rx).map_err(Report::from))
            .add_handler(
                another_handler,
                BroadcastStream::new(tx.subscribe()).map_err(Report::from),
            );

        tokio::spawn(async move {
            for i in 0..event_count {
                tx.send(events::Event::BlockEnd((i as u32).into()))
                    .expect("sending events should not fail");
            }
        });

        assert!(processor.run().await.is_ok());
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
