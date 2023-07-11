use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Invalid input: {reason}")]
    InvalidInput { reason: String },

    #[error("Invalid participants: {reason}")]
    InvalidParticipants { reason: String },

    #[error("Message is invalid: {context}")]
    InvalidMessage { context: String },
}
