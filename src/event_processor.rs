use core::future::Future;
use core::pin::Pin;
use std::vec;

use async_trait::async_trait;
use error_stack::{Context, IntoReport, Result, ResultExt};
use futures::{future::try_join_all, StreamExt};
use thiserror::Error;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use crate::event_sub::Event;
use crate::handlers::chain;

type Task = Box<dyn Future<Output = Result<(), EventProcessorError>> + Send>;

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
pub enum EventProcessorError {
    #[error("event handler failed handling event")]
    EventHandlerError,
    #[error("event stream error")]
    EventStreamError,
}

fn consume_events<H, S, E>(event_stream: S, handler: H, token: CancellationToken) -> Task
where
    H: EventHandler + Send + Sync + 'static,
    S: Stream<Item = Result<Event, E>> + Send + 'static,
{
    let task = async move {
        let mut event_stream = Box::pin(event_stream);
        while let Some(res) = event_stream.next().await {
            let event = res.change_context(EventProcessorError::EventStreamError)?;

            handler
                .handle(&event)
                .await
                .change_context(EventProcessorError::EventHandlerError)?;

            if matches!(event, Event::BlockEnd(_)) && token.is_cancelled() {
                break;
            }
        }

        Ok(())
    };

    Box::new(task)
}

pub struct EventProcessor {
    tasks: Vec<Pin<Task>>,
    token: CancellationToken,
}

impl EventProcessor {
    pub fn new(token: CancellationToken) -> Self {
        EventProcessor { tasks: vec![], token }
    }

    pub fn add_handler<H, S, E>(&mut self, handler: H, event_stream: S) -> &mut Self
    where
        H: EventHandler + Send + Sync + 'static,
        S: Stream<Item = Result<Event, E>> + Send + 'static,
    {
        self.tasks
            .push(consume_events(event_stream, handler, self.token.child_token()).into());
        self
    }

    pub async fn run(self) -> Result<(), EventProcessorError> {
        let handles = self.tasks.into_iter().map(tokio::spawn);

        try_join_all(handles)
            .await
            .into_report()
            .change_context(EventProcessorError::EventHandlerError)?
            .into_iter()
            .find(Result::is_err)
            .unwrap_or(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{EventHandler, EventProcessor};
    use crate::event_sub;
    use async_trait::async_trait;
    use error_stack::{IntoReport, Result};
    use mockall::mock;
    use thiserror::Error;
    use tokio::{self, sync::broadcast};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::StreamExt;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn should_handle_events() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<event_sub::Event>(event_count);
        let token = CancellationToken::new();
        let mut processor = EventProcessor::new(token.child_token());

        let mut handler = MockEventHandler::new();
        handler.expect_handle().returning(|_| Ok(())).times(event_count);

        tokio::spawn(async move {
            for i in 0..event_count {
                assert!(tx.send(event_sub::Event::BlockEnd((i as u32).into())).is_ok());
            }
        });

        processor.add_handler(handler, BroadcastStream::new(rx).map(IntoReport::into_report));
        assert!(processor.run().await.is_ok());
    }

    #[tokio::test]
    async fn should_return_error_if_handler_fails() {
        let (tx, rx) = broadcast::channel::<event_sub::Event>(10);
        let token = CancellationToken::new();
        let mut processor = EventProcessor::new(token.child_token());

        let mut handler = MockEventHandler::new();
        handler
            .expect_handle()
            .returning(|_| Err(EventHandlerError::Unknown).into_report())
            .once();

        tokio::spawn(async move {
            assert!(tx.send(event_sub::Event::BlockEnd((10_u32).into())).is_ok());
        });

        processor.add_handler(handler, BroadcastStream::new(rx).map(IntoReport::into_report));
        assert!(processor.run().await.is_err());
    }

    #[tokio::test]
    async fn should_support_multiple_types_of_handlers() {
        let event_count = 10;
        let (tx, rx) = broadcast::channel::<event_sub::Event>(event_count);
        let token = CancellationToken::new();
        let mut processor = EventProcessor::new(token.child_token());
        let stream = BroadcastStream::new(rx).map(IntoReport::into_report);
        let another_stream = BroadcastStream::new(tx.subscribe()).map(IntoReport::into_report);

        let mut handler = MockEventHandler::new();
        handler.expect_handle().returning(|_| Ok(())).times(event_count);

        let mut another_handler = MockAnotherEventHandler::new();
        another_handler.expect_handle().returning(|_| Ok(())).times(event_count);

        tokio::spawn(async move {
            for i in 0..event_count {
                assert!(tx.send(event_sub::Event::BlockEnd((i as u32).into())).is_ok());
            }
        });

        processor
            .add_handler(handler, stream)
            .add_handler(another_handler, another_stream);
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

                async fn handle(&self, event: &event_sub::Event) -> Result<(), EventHandlerError>;
            }
    }

    #[derive(Error, Debug)]
    pub enum AnotherEventHandlerError {}

    mock! {
            AnotherEventHandler{}

            #[async_trait]
            impl EventHandler for AnotherEventHandler {
                type Err = AnotherEventHandlerError;

                async fn handle(&self, event: &event_sub::Event) -> Result<(), AnotherEventHandlerError>;
            }
    }
}
