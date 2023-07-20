use cosmwasm_std::StdError;
use thiserror::Error;

use axelar_wasm_std::nonempty;
use connection_router;
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

    #[error("source chain mismatch")]
    SourceChainMismatch,

    #[error("message {0} mismatch with verified message")]
    MessageMismatch(String),
}
