use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to deserialize event with type `{0}` into {1} event")]
    DeserializationFailed(String, String),
    #[error("event does not match event type `{0}`")]
    EventTypeMismatch(String),
    #[error("failed to decode event attribute")]
    DecodingAttributesFailed,
}

#[derive(Error, Debug)]
pub enum DecodingError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    UTF8(#[from] std::string::FromUtf8Error),
}
