use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("type cannot be {0}")]
    InvalidValue(String),
}
