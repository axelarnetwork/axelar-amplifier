use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    RouterError(#[from] connection_router::ContractError),

    #[error("received invalid verifier reply: {0}")]
    InvalidVerifierReply(String),
}
