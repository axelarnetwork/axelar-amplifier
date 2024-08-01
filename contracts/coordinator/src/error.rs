use cosmwasm_std::StdError;
use cw2::VersionError;
use error_utils::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Version(#[from] VersionError),

    #[error("caller not unauthorized to perform this action")]
    Unauthorized,

    #[error("prover is not registered")]
    ProverNotRegistered,
}
