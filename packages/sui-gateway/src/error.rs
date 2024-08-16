use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("unsupported type of public key")]
    UnsupportedPublicKey,
    #[error("unsupported type of signature")]
    UnsupportedSignature,
}
