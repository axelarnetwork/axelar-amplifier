use error_utils::{ContractError, IntoContractError};
use thiserror::Error;

#[derive(Error, Debug, IntoContractError)]
enum TestError {
    #[error("error")]
    Something,
}

#[test]
fn can_convert_error() {
    _ = ContractError::from(TestError::Something);
}
