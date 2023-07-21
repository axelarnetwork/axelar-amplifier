use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized {},
    #[error("service name already exists")]
    ServiceAlreadyExists {},
    #[error("service not found")]
    ServiceNotFound {},
    #[error("service worker already authorized")]
    ServiceWorkerAlreadyAuthorized {},
    #[error("funds are in the wrong denomination")]
    WrongDenom {},
    #[error("worker not found")]
    WorkerNotFound {},
    #[error("invalid worker state for this operation")]
    InvalidWorkerState {},
}
