use axelar_wasm_std::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("The contract needs to be initialized first")]
    ContractInitailization,
    // This is a generic error to use when cw_storage_plus returns an error that is unexpected and
    // should never happen, such as an error encountered when saving data.
    #[error("storage error")]
    Storage,
    #[error(transparent)]
    SnarkVM(#[from] snarkvm_cosmwasm::prelude::Error),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("MultisigAleoError: {0}")]
    MultisigAleo(String),
}
