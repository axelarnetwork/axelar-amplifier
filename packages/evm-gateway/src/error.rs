use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid signature")]
    InvalidSignature,
}
