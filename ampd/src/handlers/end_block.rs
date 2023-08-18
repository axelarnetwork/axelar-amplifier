use crate::event_processor::EventHandler;
use crate::event_sub::Event;
use async_trait::async_trait;
use error_stack::{IntoReport, Result, ResultExt};
use tendermint::block;
use thiserror::Error;
use tokio::sync::mpsc::{self, Receiver};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed sending label and block height")]
    SendError,
}

struct Handler {
    tx: mpsc::Sender<block::Height>,
}

impl Handler {
    fn new() -> (Self, Receiver<block::Height>) {
        let (tx, rx) = mpsc::channel(10000);
        (Self { tx }, rx)
    }
}

pub fn with_block_height_notifier(
    handler: impl EventHandler + Send + Sync,
) -> (impl EventHandler, Receiver<block::Height>) {
    let (end_block_handler, rx) = Handler::new();
    (handler.chain(end_block_handler), rx)
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<(), Error> {
        match event {
            Event::BlockEnd(height) => self
                .tx
                .send(*height)
                .await
                .into_report()
                .change_context(Error::SendError),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_processor::EventHandler;
    use crate::event_sub;
    use crate::handlers::end_block::Handler;
    use tendermint::block;

    #[tokio::test]
    async fn handle_should_stream_blocks() {
        let count = 10;
        let (handler, mut rx) = Handler::new();
        let mut height = block::Height::default();

        for _ in 0..count {
            assert!(handler
                .handle(&event_sub::Event::BlockEnd(height))
                .await
                .is_ok());
            height = height.increment();
        }

        let mut height = block::Height::default();
        for _ in 0..count {
            let actual_height = rx.recv().await.unwrap();
            assert_eq!(actual_height, height);

            height = height.increment();
        }
    }
}
