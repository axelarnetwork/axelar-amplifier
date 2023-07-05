use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("domain name is invalid")]
    InvalidDomainName {},

    #[error("message ID is invalid")]
    InvalidMessageID {},

    #[error("address of {0} is invalid")]
    InvalidAddress(String),

    #[error("router error")]
    RouterError {
        error: connection_router::error::ContractError,
    },

    #[error("message not found")]
    MessageNotFound { message_id: String },

    #[error("message not verified")]
    MessageNotVerified { message_id: String },

    #[error("message already executed")]
    MessageAlreadyExecuted { message_id: String },

    #[error("sender is not router")]
    SenderNotRouter {},

    #[error("batch contains duplicate message ids")]
    DuplicateMessageID {},
}

impl From<connection_router::ContractError> for ContractError {
    fn from(value: connection_router::ContractError) -> Self {
        match value {
            connection_router::ContractError::InvalidAddress(addr) => Self::InvalidAddress(addr),
            connection_router::ContractError::InvalidDomainName {} => Self::InvalidDomainName {},
            connection_router::ContractError::InvalidMessageID {} => Self::InvalidDomainName {},
            _ => Self::RouterError { error: value },
        }
    }
}
