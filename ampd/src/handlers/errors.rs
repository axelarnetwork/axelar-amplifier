use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to broadcast transaction")]
    Broadcaster,
    #[error("failed to get the latest finalized block")]
    Finalizer,
    #[error("failed to deserialize the event")]
    DeserializeEvent(#[from] serde_json::Error),
}
