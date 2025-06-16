use clarity::vm::errors::{CheckErrors, Error as ClarityError};
use clarity::vm::types::serialization::SerializationError;
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

impl From<CheckErrors> for Error {
    fn from(_: CheckErrors) -> Self {
        Error::InvalidEncoding
    }
}

impl From<ClarityError> for Error {
    fn from(_: ClarityError) -> Self {
        Error::InvalidEncoding
    }
}

impl From<SerializationError> for Error {
    fn from(_: SerializationError) -> Self {
        Error::InvalidEncoding
    }
}
