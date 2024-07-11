use axelar_wasm_std_derive::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error("failed to decode ITS message: {0}")]
    InvalidMessage(String),
    #[error("failed to convert token manager type")]
    InvalidTokenManagerType,
}
