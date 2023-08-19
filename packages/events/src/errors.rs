use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to deserialize event with type `{0}` into {1} event")]
    DeserializationFailed(String, String),
    #[error("event does not match type {0}")]
    EventTypeMismatch(String),
}
