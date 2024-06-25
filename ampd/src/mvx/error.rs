use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not ed25519 key error")]
    NotEd25519Key,
    #[error("Required property is empty error")]
    PropertyEmpty,
}
