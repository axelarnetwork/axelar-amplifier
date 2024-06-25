use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::StdError;
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("no provers registered for chain {0}")]
    NoProversRegisteredForChain(ChainName),
}
