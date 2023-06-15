use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Domain name is invalid")]
    InvalidDomainName {},

    #[error("Message ID is invalid")]
    InvalidMessageID {},

    #[error("Address is invalid")]
    InvalidAddress {},

    #[error("Router error")]
    RouterError {
        error: connection_router::error::ContractError,
    },
}

impl From<connection_router::ContractError> for ContractError {
    fn from(value: connection_router::ContractError) -> Self {
        match value {
            connection_router::ContractError::InvalidAddress {} => Self::InvalidAddress {},
            connection_router::ContractError::InvalidDomainName {} => Self::InvalidDomainName {},
            connection_router::ContractError::InvalidMessageID {} => Self::InvalidDomainName {},
            _ => Self::RouterError { error: value },
        }
    }
}
