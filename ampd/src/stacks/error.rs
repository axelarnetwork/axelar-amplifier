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
