use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to deserialize the event")]
    DeserializeEvent,
    #[error("failed to get the latest finalized block")]
    Finalizer,
    #[error("unsupported key type {0}")]
    KeyType(String),
    #[error("failed to prepare message for signing")]
    MessageToSign,
    #[error("failed to parse public key")]
    PublicKey,
    #[error("failed to get signature from tofnd")]
    Sign,
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("failed to get transaction receipts")]
    TxReceipts,
}
