use connection_router::state::MessageId;
use cosmwasm_std::HexBinary;
use thiserror::Error;

use axelar_wasm_std_derive::IntoContractError;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("caller is not authorized")]
    Unauthorized,

    #[error("invalid message id {0}")]
    InvalidMessageId(MessageId),

    #[error("invalid payload hash {0}")]
    InvalidMessagePayloadHash(HexBinary),
}
