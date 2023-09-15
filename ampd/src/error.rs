use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to load config, falling back on default")]
    LoadConfig,
    #[error("{0} is not a valid location to persist state")]
    StateLocation(String),
    #[error("event sub failed")]
    EventSub,
    #[error("event processor failed")]
    EventProcessor,
    #[error("broadcaster failed")]
    Broadcaster,
    #[error("state updater failed")]
    StateUpdater,
    #[error("tofnd failed")]
    Tofnd,
    #[error("connection failed")]
    Connection,
    #[error("task execution failed")]
    Task,
}
