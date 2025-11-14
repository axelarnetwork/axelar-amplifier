use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to start")]
    HandlerStart,
    #[error("handler task failed")]
    HandlerTask,
    #[error("failed to handle event")]
    EventHandling,
    #[error("failed to prepare message for signing")]
    MessageToSign,
    #[error("failed to get signature from tofnd")]
    Sign,
    #[error("failed to get key id")]
    KeyId,
}
