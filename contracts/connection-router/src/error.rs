use cosmwasm_std::StdError;
use thiserror::Error;

use crate::types::ChainName;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("caller is not authorized")]
    Unauthorized,

    #[error("chain already exists")]
    ChainAlreadyExists,

    #[error("chain name is invalid")]
    InvalidChainName,

    #[error("message ID is invalid")]
    InvalidMessageID,

    #[error("chain is not found")]
    ChainNotFound,

    #[error("gateway is not registered")]
    GatewayNotRegistered,

    #[error("gateway is already registered")]
    GatewayAlreadyRegistered,

    #[error("chain is frozen")]
    ChainFrozen { chain: ChainName },

    #[error("address of {0} is invalid")]
    InvalidAddress(String),

    #[error("source chain does not match registered gateway")]
    WrongSourceChain,
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
