use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    RouterError(#[from] connection_router::ContractError),

    #[error("received invalid verifier reply: {0}")]
    InvalidVerifierReply(String),
}
