use axelar_wasm_std::IntoContractError;
use cosmwasm_std::Coin;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error("store failed saving/loading data")]
    StoreFailure,

    #[error("invalid token: one and only one token is required for this operation, got {0:?}")]
    InvalidToken(Vec<Coin>),

    #[error("failed querying the axelarnet gateway")]
    AxelarnetGateway,

    #[error("failed converting the nexus message for the router")]
    InvalidNexusMessageForRouter,

    #[error("failed to query the nexus module")]
    Nexus,

    #[error("nonce from the nexus module overflowed u32")]
    NonceOverflow,
}
