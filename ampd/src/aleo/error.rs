use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Request error: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    // #[error("Request error")]
    // Request,
    #[error("Transaction '{0}' not found")]
    TransactionNotFound(String),
    #[error("Transition '{0}' not found")]
    TransitionNotFound(String),
    #[error("Failed to find callContract")]
    CallContractNotFound,
    #[error("Failed to find signerRotation")]
    SignerRotationNotFound,
    // #[error("The program name is invalid: {0}")]
    // InvalidProgramName(String),
    #[error("The provided chain name is invalid")]
    InvalidChainName,
    #[error("Invalid destination address")]
    InvalidDestinationAddress,
    #[error("Failed to find transition '{0}' in transaction")]
    TransitionNotFoundInTransaction(String),
    // #[error("Failed to create CallContract receipt: {0}")]
    // CalledContractReceipt(String),
    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Axelar nonempty error: {0}")]
    AxelarNonempty(#[from] axelar_wasm_std::nonempty::Error),
    #[error("Router API error: {0}")]
    RouterApi(#[from] router_api::error::Error),
    #[error("SnarkVM error: {0}")]
    SnarkVM(#[from] snarkvm::prelude::Error),
    #[error("Aleo string encoder error: {0}")]
    AleoStringEncoder(#[from] aleo_string_encoder::Error),
}
