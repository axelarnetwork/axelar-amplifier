use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to start")]
    HandlerStart,
    #[error("handler task failed")]
    HandlerTask,
    #[error("failed to get finalized transaction blocks")]
    FinalizedTxs,
}
