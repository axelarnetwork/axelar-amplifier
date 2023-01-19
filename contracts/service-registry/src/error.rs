use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},
    #[error("Service name already exists")]
    ServiceAlreadyExists {},
    #[error("Service does not exists")]
    ServiceNotExists {},
    #[error("Service worker already registered")]
    ServiceWorkerAlreadyRegistered {},
    #[error("Funds don't meet minimum requirement for bonding")]
    NotEnoughFunds {},
    #[error("Worker not registered for this service")]
    UnregisteredWorker {},
    #[error("Invalid worker state for this operation")]
    InvalidWorkerState {},
    #[error("{msg}")]
    ServiceContractError { msg: String },
}
