use cosmwasm_std::StdError;
use thiserror::Error;

use crate::types::ChainName;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not authorized")]
    Unauthorized {},

    #[error("Chain already exists")]
    ChainAlreadyExists {},

    #[error("Chain name is invalid")]
    InvalidChainName {},

    #[error("Message ID is invalid")]
    InvalidMessageID {},

    #[error("Chain was not found")]
    ChainNotFound {},

    #[error("Gateway is not registered")]
    GatewayNotRegistered {},

    #[error("Gateway was already registered")]
    GatewayAlreadyRegistered {},

    #[error("Chain is frozen")]
    ChainFrozen { chain: ChainName },

    #[error("Address is invalid")]
    InvalidAddress {},

    #[error("Source chain does not match registered gateway")]
    WrongSourceChain {},
}
