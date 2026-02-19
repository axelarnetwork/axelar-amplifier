use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to start")]
    HandlerStart,
    #[error("handler task failed")]
    HandlerTask,
    #[error("task group execution failed")]
    TaskGroup,
    #[error("Error parsing domain separator from config")]
    DomainSeparator,
    #[error("Error parsing gateway address")]
    GatewayAddress,
}
