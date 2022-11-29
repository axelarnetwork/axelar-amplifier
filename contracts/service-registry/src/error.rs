use cosmwasm_std::{Coin, StdError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},
    #[error("Missing AXL asset")]
    AxlAssetMissing {},
    #[error("Service name already exists")]
    ServiceAlreadyExists {},
    #[error("Service does not exists")]
    ServiceNotExists {},
    #[error("Service worker already registered")]
    ServiceWorkerAlreadyRegistered {},
    #[error("Funds don't meet minimum requirement for bonding: {assets:?}")]
    NotEnoughFunds { assets: Vec<Coin> },
    #[error("Trying to bond unsupported asset")]
    UnsupportedAssetBond {},
    #[error("Worker not registered for this service")]
    UnregisteredWorker {},
    #[error("Invalid worker state for this operation")]
    InvalidWorkerState {},
    #[error("{msg}")]
    ServiceContractError { msg: String },
}
