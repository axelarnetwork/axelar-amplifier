use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("caller is not authorized")]
    Unauthorized {},

    #[error("message is invalid: {reason}")]
    InvalidMessage { reason: String },

    #[error("public key not found for participant {participant}")]
    PublicKeyNotFound { participant: String },

    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },

    #[error("invalid participants: {reason}")]
    InvalidParticipants { reason: String },

    #[error("no messages found")]
    NoMessagesFound {},

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },
}
