use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("message is invalid: {reason}")]
    InvalidMessage { reason: String },

    #[error("public key not found for participant {participant}")]
    PublicKeyNotFound { participant: String },
}
