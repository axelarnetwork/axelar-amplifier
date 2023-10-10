use cosmwasm_std::StdError;
use error_stack::{Context, Report};
use report::LoggableError;
use thiserror::Error;

/// This error is supposed to be the top-level error type our contracts return to the cosmwasm module.
/// Ideally, we would like to return an error-stack [Report] directly,
/// but it won't show all necessary information (namely attachments) in the error message, and many places also return an [StdError].
/// To this end, reports get converted into [LoggableError] and this [ContractError] type unifies [LoggableError] and [StdError],
/// so we can return both to cosmwasm.
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
