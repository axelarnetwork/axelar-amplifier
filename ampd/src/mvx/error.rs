use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("provided key is not ed25519")]
    NotEd25519Key,
    #[error("required property is empty")]
    PropertyEmpty,
}
