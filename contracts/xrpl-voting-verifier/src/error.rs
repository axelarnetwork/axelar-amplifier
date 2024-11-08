use axelar_wasm_std::{nonempty, voting, IntoContractError};
use cosmwasm_std::{OverflowError, StdError};
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("empty batch of messages")]
    EmptyMessages,

    #[error("invalid source gateway address")]
    InvalidSourceGatewayAddress,

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error("poll not found")]
    PollNotFound,

    #[error("all messages must have the same source chain {0}")]
    SourceChainMismatch(ChainName),

    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    VoteError(#[from] voting::Error),
}
