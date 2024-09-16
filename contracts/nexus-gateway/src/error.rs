use axelar_wasm_std::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error("store failed saving/loading data")]
    StoreFailure,

    #[error("invalid token received")]
    InvalidToken,

    #[error("failed querying the axelarnet gateway")]
    AxelarnetGateway,

    #[error("failed converting the nexus message for the router")]
    InvalidNexusMessageForRouter,
}
