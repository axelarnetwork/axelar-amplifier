use axelar_wasm_std::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

/// The shared error type for the chain-codec implementations in this repository.
/// If you are implementing a new chain-codec implementation, you are free to use a different error type if you want.
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

    #[error("failed to serialize data for the external gateway")]
    SerializeData,
}
