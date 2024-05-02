use crate::event_processor::EventHandler;
use async_trait::async_trait;
use cosmrs::Any;
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

    async fn handle(&self, event: &Event) -> Result<Vec<Any>, Error> {
        let msgs_1 = self
            .handler_1
            .handle(event)
            .await
            .change_context(Error::ChainError)?;
        let msgs_2 = self
            .handler_2
            .handle(event)
            .await
            .change_context(Error::ChainError)?;

        Ok(msgs_1.into_iter().chain(msgs_2).collect())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use cosmrs::tx::Msg;
    use cosmrs::{bank::MsgSend, AccountId, Any};
    use error_stack::Result;
    use events::Event;
    use mockall::{mock, predicate};
    use tendermint::block;
    use thiserror::Error;

    use crate::event_processor::{self, EventHandler};

    #[tokio::test]
    async fn should_chain_handlers() {
        let height: block::Height = (10_u32).into();
        let msg_1 = dummy_msg(AccountId::new("", &[1, 2, 3]).unwrap());
        let msg_2 = dummy_msg(AccountId::new("", &[2, 3, 4]).unwrap());
        let msg_3 = dummy_msg(AccountId::new("", &[3, 4, 5]).unwrap());

        let mut handler_1 = MockEventHandler::new();
        let msgs_1 = vec![msg_1.clone()];
        handler_1
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(move |_| Ok(msgs_1.clone()));
        let mut handler_2 = MockEventHandler::new();
        let msgs_2 = vec![msg_2.clone(), msg_3.clone()];
        handler_2
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(move |_| Ok(msgs_2.clone()));

        assert_eq!(
            handler_1
                .chain(handler_2)
                .handle(&Event::BlockEnd(height))
                .await
                .unwrap(),
            vec![msg_1, msg_2, msg_3]
        );
    }

    #[tokio::test]
    async fn should_fail_if_the_first_handler_fails() {
        let height: block::Height = (10_u32).into();

        let mut handler_1 = MockEventHandler::new();
        handler_1
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Err(EventHandlerError::Unknown.into()));

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
            .returning(|_| Ok(vec![]));
        let mut handler_2 = MockEventHandler::new();
        handler_2
            .expect_handle()
            .once()
            .with(predicate::eq(Event::BlockEnd(height)))
            .returning(|_| Err(EventHandlerError::Unknown.into()));

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

                async fn handle(&self, event: &Event) -> Result<Vec<Any>, EventHandlerError>;
            }
    }

    fn dummy_msg(from_address: AccountId) -> Any {
        MsgSend {
            from_address,
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
