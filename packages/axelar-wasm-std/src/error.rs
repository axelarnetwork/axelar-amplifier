use cosmwasm_std::StdError;
use error_stack::{Context, Report};
use report::LoggableError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Structured(#[from] LoggableError),
}

impl<T> From<Report<T>> for ContractError
where
    T: Context,
{
    fn from(report: Report<T>) -> Self {
        ContractError::Structured(LoggableError::from(&report))
    }
}
