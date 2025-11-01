use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to start")]
    HandlerStart,
    #[error("failed to handle event")]
    EventHandling,
    #[error("handler task failed")]
    HandlerTask,
    #[error("failed to get the latest finalized block")]
    Finalizer,
}
