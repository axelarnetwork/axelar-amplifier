use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StringEncoderError(#[from] aleo_string_encoder::Error),
    #[error(transparent)]
    RouterApi(#[from] router_api::error::Error),
    #[error("Invalid chain name: {0}")]
    InvalidChainName(String),
}
