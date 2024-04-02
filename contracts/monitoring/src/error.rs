use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("no provers registered for chain")]
    NoProversRegisteredForChain,
}