use axelar_wasm_std::nonempty;
use cosmwasm_std::StdError;
use thiserror::Error;

use crate::state::BondingState;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),

    #[error("unauthorized")]
    Unauthorized,
    #[error("service name already exists")]
    ServiceAlreadyExists,
    #[error("service not found")]
    ServiceNotFound,
    #[error("worker already authorized")]
    WorkerAlreadyAuthorized,
    #[error("funds are in the wrong denomination")]
    WrongDenom,
    #[error("worker not found")]
    WorkerNotFound,
    #[error("invalid bonding state `{0:?}` for this operation")]
    InvalidBondingState(BondingState),
}
