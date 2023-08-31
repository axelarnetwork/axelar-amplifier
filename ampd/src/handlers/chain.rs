use crate::event_processor::EventHandler;
use async_trait::async_trait;
use error_stack::{Result, ResultExt};
use events::Event;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("one of the chained handlers failed handling event")]
    ChainError,
}

pub struct Handler<H1, H2>
where
    H1: EventHandler,
    H2: EventHandler,
{
    handler_1: H1,
    handler_2: H2,
}

impl<H1, H2> Handler<H1, H2>
where
    H1: EventHandler,
    H2: EventHandler,
{
    pub fn new(handler_1: H1, handler_2: H2) -> Self {
        Self {
            handler_1,
            handler_2,
        }
    }
}

#[async_trait]
impl<H1, H2> EventHandler for Handler<H1, H2>
where
    H1: EventHandler + Send + Sync,
    H2: EventHandler + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<(), Error> {
        self.handler_1
            .handle(event)
            .await
            .change_context(Error::ChainError)?;
        self.handler_2
            .handle(event)
            .await
            .change_context(Error::ChainError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::event_processor::{self, EventHandler};
    use async_trait::async_trait;
    use error_stack::{IntoReport, Result};
    use events::Event;
    use mockall::{mock, predicate};
    use tendermint::block;
    use thiserror::Error;

    #[tokio::test]
    async fn should_chain_handlers() {
        let height: block::Height = (10_u32).into();

        let mut handler_1 = MockEventHandler::new();
        handler_1
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Ok(()));
        let mut handler_2 = MockEventHandler::new();
        handler_2
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Ok(()));

        assert!(handler_1
            .chain(handler_2)
            .handle(&Event::BlockEnd(height))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn should_fail_if_the_first_handler_fails() {
        let height: block::Height = (10_u32).into();

        let mut handler_1 = MockEventHandler::new();
        handler_1
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Err(EventHandlerError::Unknown).into_report());

        assert!(handler_1
            .chain(MockEventHandler::new())
            .handle(&Event::BlockEnd(height))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_fail_if_the_second_handler_fails() {
        let height: block::Height = (10_u32).into();

        let mut handler_1 = MockEventHandler::new();
        handler_1
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Ok(()));
        let mut handler_2 = MockEventHandler::new();
        handler_2
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Err(EventHandlerError::Unknown).into_report());

        assert!(handler_1
            .chain(handler_2)
            .handle(&Event::BlockEnd(height))
            .await
            .is_err());
    }

    #[derive(Error, Debug)]
    pub enum EventHandlerError {
        #[error("unknown")]
        Unknown,
    }

    mock! {
            EventHandler{}

            #[async_trait]
            impl event_processor::EventHandler for EventHandler {
                type Err = EventHandlerError;

                async fn handle(&self, event: &Event) -> Result<(), EventHandlerError>;
            }
    }
}
