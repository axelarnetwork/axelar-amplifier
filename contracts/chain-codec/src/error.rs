use axelar_wasm_std::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, IntoContractError)]
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
