use crate::event_processor::EventHandler;
use crate::event_sub::Event;
use async_trait::async_trait;
use error_stack::{IntoReport, Result, ResultExt};
use tendermint::block;
use thiserror::Error;
use tokio::sync::mpsc;

type LabelBlock = (String, block::Height);

#[derive(Error, Debug)]
pub enum EndBlockHandlerError {
    #[error("failed sending label and block height")]
    SendError,
}

pub struct EndBlockHandlerFactory {
    tx: mpsc::Sender<LabelBlock>,
}

impl EndBlockHandlerFactory {
    pub fn new(tx: mpsc::Sender<LabelBlock>) -> Self {
        Self { tx }
    }

    pub fn build(&self, label: String) -> EndBlockHandler {
        EndBlockHandler {
            label,
            tx: self.tx.clone(),
        }
    }
}

pub struct EndBlockHandler {
    label: String,
    tx: mpsc::Sender<LabelBlock>,
}

#[async_trait]
impl EventHandler for EndBlockHandler {
    type Err = EndBlockHandlerError;

    async fn handle(&self, event: &Event) -> Result<(), EndBlockHandlerError> {
        match event {
            Event::BlockEnd(height) => self
                .tx
                .send((self.label.clone(), *height))
                .await
                .into_report()
                .change_context(EndBlockHandlerError::SendError),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_processor::EventHandler;
    use crate::event_sub;
    use crate::handlers::end_block_handler::EndBlockHandlerFactory;
    use tendermint::block;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn handle_should_stream_blocks() {
        let count = 10;
        let (tx, mut rx) = mpsc::channel(count);
        let factory = EndBlockHandlerFactory::new(tx);
        let label = "handler";
        let handler = factory.build(label.into());
        let mut height = block::Height::default();

        for _ in 0..count {
            assert!(handler.handle(&event_sub::Event::BlockEnd(height)).await.is_ok());
            height = height.increment();
        }

        let mut height = block::Height::default();
        for _ in 0..count {
            let (actual_label, actual_height) = rx.recv().await.unwrap();

            assert_eq!(actual_label, label);
            assert_eq!(actual_height, height);

            height = height.increment();
        }
    }
}
