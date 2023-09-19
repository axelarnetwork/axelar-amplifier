use cosmwasm_std::StdError;
use report::LoggableError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Structured(#[from] LoggableError),
}
