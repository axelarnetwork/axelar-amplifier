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

/// Asserts that the Report contains the specified error type and pattern.
/// If the report does not contain the specified error type and pattern,
/// the error will be displayed in the assert message.
///
/// # Examples
///
/// ```
/// use axelar_wasm_std::error::{err_contains};
/// use error_stack::Report;
///
/// #[derive(thiserror::Error, Debug)]
/// enum Error {
///     #[error("invalid")]
///     Invalid,
/// }
///
/// let result: Result<u8, Report<Error>> = Err(Report::new(Error::Invalid));
/// let err = result.unwrap_err();
/// assert!(err_contains!(err, Error, Error::Invalid));
/// ```
#[macro_export]
macro_rules! err_contains {
    ($expression:expr, $error_type:ty, $pattern:pat $(if $guard:expr)? $(,)?) => {
        match $expression.downcast_ref::<$error_type>() {
            Some($pattern) $(if $guard)? => true,
            _ => {
                println!("expected error: {}{}\n", stringify!($pattern), stringify!($( if $guard)?));
                println!("actual: {:?}", $expression);

                false
            }
        }
    };
}

/// Asserts that the result is an error and contains the specified error type and pattern.
/// Any `Result<T, E>` such that `E: Into<ContractError>` can be used.
/// If the result is not an error, or the error does not match the specified type and pattern,
/// the result will be displayed in the assert message.
///
/// # Examples
///
/// ```
/// use axelar_wasm_std::{error::{assert_err_contains, ContractError, self}};
/// use error_stack::{report, Report};
///
/// #[derive(thiserror::Error, Debug)]
/// enum Error {
///     #[error("invalid")]
///     Invalid,
/// }
///
/// impl From<Error> for ContractError {
///     fn from(err: Error) -> Self {
///         ContractError {
///             report: report!(err).change_context(error::Error::Report),
///         }
///     }
/// }
///
/// let result: Result<u8, Error> = Err(Error::Invalid);
/// assert_err_contains!(result, Error, Error::Invalid);
///
/// let result: Result<u8, Report<Error>> = Err(Report::new(Error::Invalid));
/// assert_err_contains!(result, Error, Error::Invalid);
///
/// let result: Result<u8, ContractError> = Err(Error::Invalid.into());
/// assert_err_contains!(result, Error, Error::Invalid);
/// ```
#[macro_export]
macro_rules! assert_err_contains {
    ($expression:expr, $error_type:ty, $pattern:pat $(if $guard:expr)? $(,)?) => {{
        let assert_statement = stringify!(assert_err_contains!($expression, $error_type, $pattern $(if $guard)?));
        match $expression {
            Ok(value) => {
                assert!(
                    false,
                    "\nassertion failed: {}\n\nexpected error: {}\n\nactual: Ok({:?})",
                    assert_statement,
                    stringify!($pattern $(if $guard)?),
                    value
                );
            },
            Err(err) => {
                let contract_err = $crate::error::ContractError::from(err).report;

                match contract_err.downcast_ref::<$error_type>() {
                    Some($pattern) $(if $guard)? => {},
                    _ => {
                        assert!(
                            false,
                            "\nassertion failed: {}\n\nexpected error: {}\n\nactual: {:?}",
                            assert_statement,
                            stringify!($pattern $(if $guard)?),
                            contract_err
                        );
                    }
                }
            }
        }
    }};
}

pub use {assert_err_contains, err_contains};

#[cfg(test)]
mod test {
    use error_stack::{report, Report};

    use super::ContractError;

    #[derive(thiserror::Error, Debug)]
    enum TestError {
        #[error("one")]
        One,
        #[error("two")]
        Two,
    }

    // Can't use IntoContractError to derive this since axelar-wasm-std crate can't be referenced from within without a self dependency
    impl From<TestError> for ContractError {
        fn from(err: TestError) -> Self {
            ContractError {
                report: report!(err).change_context(super::Error::Report),
            }
        }
    }

    #[test]
    fn assert_error_succeeds() {
        let result: Result<u8, TestError> = Err(TestError::One);
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    fn assert_report_error_succeeds() {
        let result: Result<u8, Report<TestError>> = Err(report!(TestError::One));
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    fn assert_contract_error_succeeds() {
        let result: Result<u8, ContractError> = Err(TestError::One.into());
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    #[should_panic(expected = "expected error: TestError::One")]
    fn assert_different_error_fails() {
        let result: Result<u8, TestError> = Err(TestError::Two);
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    #[should_panic(expected = "expected error: TestError::One")]
    fn assert_ok_fails() {
        let result: Result<u8, TestError> = Ok(1);
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    #[should_panic(expected = "expected error: TestError::One")]
    fn assert_ok_report_error_fails() {
        let result: Result<u8, Report<TestError>> = Ok(1);
        assert_err_contains!(result, TestError, TestError::One);
    }

    #[test]
    #[should_panic(expected = "expected error: TestError::One")]
    fn assert_ok_contract_error_fails() {
        let result: Result<u8, ContractError> = Ok(1);
        assert_err_contains!(result, TestError, TestError::One);
    }
}
