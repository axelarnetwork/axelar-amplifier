use cosmwasm_std::StdError;
use thiserror::Error;

use axelar_wasm_std_derive::IntoContractError;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("caller is not authorized")]
    Unauthorized,
}
