use thiserror::Error;
use cosmwasm_std::StdError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),
    
    #[error("translation failed")]
    TranslationFailed,
    
    #[error("serialization failed")]
    SerializationFailed,
    
    #[error("unsupported operation")]
    UnsupportedOperation,
} 