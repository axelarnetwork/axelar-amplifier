use axelar_wasm_std_derive::IntoContractError;
use connection_router_api::ChainName;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("caller not unauthorized to perform this action")]
    Unauthorized,

    #[error("no provers registered for chain {0}")]
    NoProversRegisteredForChain(ChainName),
}
