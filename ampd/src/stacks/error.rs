use clarity_serialization::errors::CodecError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("required property is empty")]
    PropertyEmpty,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("provided key is not ecdsa")]
    NotEcdsaKey,
}

impl From<CodecError> for Error {
    fn from(_: CodecError) -> Self {
        Error::InvalidEncoding
    }
}
