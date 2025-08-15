use axelar_wasm_std::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    StringEncoderError(#[from] aleo_string_encoder::Error),
    #[error(transparent)]
    AxelarInvalidChainName(#[from] axelar_wasm_std::chain::Error),
    #[error("Invalid chain name: {0}")]
    InvalidChainName(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error(transparent)]
    SnarkVM(#[from] snarkvm_cosmwasm::prelude::Error),
    #[error("Conversion failed")]
    ConversionFailed,
}
