use axelar_wasm_std::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

use crate::ChainName;

/// A chain name must adhere to the following rules:
/// 1. it can optionally start with an uppercase letter, followed by one or more lowercase letters
/// 2. it can have an optional suffix of an optional dash and one or more digits ("1", "03", "-5" are all valid suffixes)
pub const CHAIN_NAME_REGEX: &str = "^[A-Z]?[a-z]+(-?[0-9]+)?$";

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("amplifier routing is disabled")]
    RoutingDisabled,

    #[error("chain already exists")]
    ChainAlreadyExists,

    #[error("chain name is invalid")]
    InvalidChainName,

    #[error("message ID is invalid")]
    InvalidMessageId,

    #[error("chain is not found")]
    ChainNotFound,

    #[error("gateway is not registered")]
    GatewayNotRegistered,

    #[error("gateway is already registered")]
    GatewayAlreadyRegistered,

    #[error("chain is frozen")]
    ChainFrozen { chain: ChainName },

    #[error("address is invalid")]
    InvalidAddress,

    #[error("source chain does not match registered gateway")]
    WrongSourceChain,

    #[error("store failed saving/loading data")]
    StoreFailure,
}
