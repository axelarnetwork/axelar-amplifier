use axelar_wasm_std::IntoContractError;
use cosmwasm_std::HexBinary;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
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
}
