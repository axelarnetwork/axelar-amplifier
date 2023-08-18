use cosmwasm_std::StdError;
use thiserror::Error;

use axelar_wasm_std::{nonempty, voting};
use connection_router;
use connection_router::types::ChainName;
use service_registry;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    RouterError(#[from] connection_router::ContractError),

    #[error("{0}")]
    NonEmptyError(#[from] nonempty::Error),

    #[error("{0}")]
    ServiceRegistryError(#[from] service_registry::ContractError),

    #[error("empty batch of messages")]
    EmptyMessages,

    #[error("all messages must have the same source chain {0}")]
    SourceChainMismatch(ChainName),

    #[error("message {0} mismatch with verified message")]
    MessageMismatch(String),

    #[error("invalid message id {0}")]
    InvalidMessageID(String),

    #[error("poll not found")]
    PollNotFound,

    #[error("{0}")]
    VoteError(#[from] voting::Error),
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
