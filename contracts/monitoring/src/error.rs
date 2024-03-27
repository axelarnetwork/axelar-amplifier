use axelar_wasm_std::nonempty;
use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),

    #[error("unauthorized")]
    Unauthorized,
}
