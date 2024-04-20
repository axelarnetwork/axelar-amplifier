use axelar_wasm_std::{nonempty, voting};
use axelar_wasm_std_derive::IntoContractError;
use connection_router_api::ChainName;
use cosmwasm_std::{OverflowError, StdError};
use service_registry;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error(transparent)]
    RouterError(#[from] connection_router_api::error::Error),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error(transparent)]
    ServiceRegistryError(#[from] service_registry::ContractError),

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
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
