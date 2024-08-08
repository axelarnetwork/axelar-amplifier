use axelar_wasm_std::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error("failed to decode ITS message")]
    InvalidMessage,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("invalid chain name")]
    InvalidChainName,
    #[error("invalid token manager type")]
    InvalidTokenManagerType,
}
