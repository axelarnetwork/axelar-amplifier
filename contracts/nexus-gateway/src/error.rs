use thiserror::Error;

use axelar_wasm_std_derive::IntoContractError;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("caller is not authorized")]
    Unauthorized,
}
