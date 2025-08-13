use cosmwasm_std::StdError;
use thiserror::Error;

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
    #[error("The contract needs to be initialized first")]
    ContractInitailization,
    #[error("storage error")]
    Storage,
}
