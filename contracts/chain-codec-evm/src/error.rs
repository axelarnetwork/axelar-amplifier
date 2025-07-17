use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("invalid verifier set")]
    InvalidVerifierSet,

    #[error("invalid payload")]
    InvalidPayload,

    #[error("failed to create proof")]
    Proof,

    #[error("message is invalid")]
    InvalidMessage,
}
