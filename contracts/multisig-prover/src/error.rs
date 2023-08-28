use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("caller is not authorized")]
    Unauthorized,

    #[error("message is invalid: {reason}")]
    InvalidMessage { reason: String },

    #[error("public key is invalid: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("chain name is invalid")]
    InvalidChainName,

    #[error("invalid participants: {reason}")]
    InvalidParticipants { reason: String },

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },
}
