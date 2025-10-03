use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("expected length {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}
