use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized {},
    #[error("service name already exists")]
    ServiceAlreadyExists {},
    #[error("service does not exist")]
    ServiceNotExists {},
    #[error("service worker already registered")]
    ServiceWorkerAlreadyRegistered {},
    #[error("funds don't meet minimum requirement for bonding")]
    NotEnoughFunds {},
    #[error("worker not registered for this service")]
    UnregisteredWorker {},
    #[error("invalid worker state for this operation")]
    InvalidWorkerState {},
    #[error("worker unbonding too early")]
    UnbondTooEarly {},

    #[error("{msg}")]
    ServiceContractError { msg: String },
}
