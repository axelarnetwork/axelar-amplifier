use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("unsupported type of public key")]
    UnsupportedPublicKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid destination address")]
    InvalidDestinationAddress,
    #[error("unsupported type of signature")]
    UnsupportedSignature,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("conversion failed")]
    ConversionFailed,
}
