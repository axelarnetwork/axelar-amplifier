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
}

impl From<connection_router::ContractError> for ContractError {
    fn from(value: connection_router::ContractError) -> Self {
        match value {
            connection_router::ContractError::InvalidAddress(address) => {
                Self::InvalidAddress(address)
            }
            connection_router::ContractError::InvalidDomainName {} => Self::InvalidDomainName {},
            connection_router::ContractError::InvalidMessageID {} => Self::InvalidMessageID {},
            _ => Self::RouterError { error: value },
        }
    }
}
