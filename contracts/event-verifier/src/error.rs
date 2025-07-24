use axelar_wasm_std::{nonempty, voting, IntoContractError};
use cosmwasm_std::{OverflowError, StdError};
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error(transparent)]
    RouterError(#[from] router_api::error::Error),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error("failed to build verifier snapshot")]
    FailedToBuildSnapshot,

    #[error("empty batch of messages")]
    EmptyMessages,

    #[error("all messages must have the same source chain {0}")]
    SourceChainMismatch(ChainName),

    #[error("invalid message id {0}")]
    InvalidMessageID(String),

    #[error("poll not found")]
    PollNotFound,

    #[error(transparent)]
    VoteError(#[from] voting::Error),

    #[error("unauthorized")]
    Unauthorized,

    #[error("poll results have different length")]
    PollResultsLengthUnequal,

    #[error("invalid source address")]
    InvalidSourceAddress,

    #[error("invalid source gateway address")]
    InvalidSourceGatewayAddress,

    // Generic error to wrap cw_storage_plus errors
    // This should only be used for things that shouldn't happen, such as encountering
    // an error when loading data that should load successfully. For errors that can
    // happen in the normal course of things, such as a user querying for a poll that doesn't
    // exist, use a more descriptive error.
    #[error("storage error")]
    StorageError,
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
