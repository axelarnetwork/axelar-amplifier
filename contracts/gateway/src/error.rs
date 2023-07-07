use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    RouterError(#[from] connection_router::ContractError),

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
