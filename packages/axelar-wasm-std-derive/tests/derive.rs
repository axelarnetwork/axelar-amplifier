use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::IntoContractError;
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
