use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    RouterError(#[from] connection_router::ContractError),

    #[error("sender is not router")]
    SenderNotRouter,

    #[error("batch contains duplicate message ids")]
    DuplicateMessageID,
}
