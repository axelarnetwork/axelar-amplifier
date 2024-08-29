use std::fmt::{Display, Formatter};

use cosmwasm_std::StdError;
use error_stack::{report, Context, Report};
use report::LoggableError;
use thiserror::Error;

use crate::permission_control;

/// This error is supposed to be the top-level error type our contracts return to the cosmwasm module.
/// Ideally, we would like to return an error-stack [Report] directly,
/// but it won't show all necessary information (namely attachments) in the error message, and many places also return an [StdError].
/// To this end, reports get converted into [LoggableError] and this [ContractError] type unifies [LoggableError] and [StdError],
/// so we can return both to cosmwasm.
#[derive(Error, Debug)]
pub struct ContractError {
    pub report: Report<Error>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("")]
    Report,
}

impl From<StdError> for ContractError {
    fn from(err: StdError) -> Self {
        ContractError {
            report: report!(err).change_context(Error::Report),
        }
    }
}

impl From<cw2::VersionError> for ContractError {
    fn from(err: cw2::VersionError) -> Self {
        ContractError {
            report: report!(err).change_context(Error::Report),
        }
    }
}

impl From<permission_control::Error> for ContractError {
    fn from(err: permission_control::Error) -> Self {
        ContractError {
            report: report!(err).change_context(Error::Report),
        }
    }
}

impl<T> From<Report<T>> for ContractError
where
    T: Context,
{
    fn from(report: Report<T>) -> Self {
        ContractError {
            report: report.change_context(Error::Report),
        }
    }
}

impl Display for ContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        LoggableError::from(&self.report).fmt(f)
    }
}

/// Merges two error reports into one. If the result is Ok, the added error is returned.
pub fn extend_err<T, E: Context>(
    result: error_stack::Result<T, E>,
    added_error: Report<E>,
) -> error_stack::Result<T, E> {
    if let Err(mut base_err) = result {
        base_err.extend_one(added_error);
        Err(base_err)
    } else {
        Err(added_error)
    }
}

#[macro_export]
macro_rules! err_contains {
    ($expression:expr, $error_type:ty, $pattern:pat $(if $guard:expr)? $(,)?) => {
        match $expression.downcast_ref::<$error_type>() {
            Some($pattern) $(if $guard)? => true,
            _ => {
                println!("actual: {:?}", $expression);

                false
            }
        }
    };
}

pub use err_contains;
