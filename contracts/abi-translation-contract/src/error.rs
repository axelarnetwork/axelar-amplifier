use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("translation failed")]
    TranslationFailed,
    
    #[error("serialization failed")]
    SerializationFailed,
    
    #[error("unsupported operation")]
    UnsupportedOperation,
} 