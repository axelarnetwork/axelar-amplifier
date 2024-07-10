use cosmwasm_std::HexBinary;
use thiserror::Error;

use axelar_wasm_std_derive::IntoContractError;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("caller is not authorized")]
    Unauthorized,

    #[error("store failed saving/loading data")]
    StoreFailure,

    #[error("invalid message id {0}")]
    InvalidMessageId(String),

    #[error("invalid source tx id {0}")]
    InvalidSourceTxId(String),

    #[error("invalid event index {0}")]
    InvalidEventIndex(u64),

    #[error("invalid payload hash {0}")]
    InvalidMessagePayloadHash(HexBinary),

    #[error("failed routing messages to the nexus module")]
    RouteToNexus,

    #[error("failed routing messages to the router")]
    RouteToRouter,

    #[error("invalid destination chain {0}")]
    InvalidDestinationChain(String),
}
