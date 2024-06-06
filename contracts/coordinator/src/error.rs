use crate::state::{ProverAddress, VerifierAddress};
use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::StdError;
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("caller not unauthorized to perform this action")]
    Unauthorized,

    #[error("no provers registered for chain {0}")]
    NoProversRegisteredForChain(ChainName),

    #[error("verifier {0} not found for prover {1}")]
    NoSuchVerifierRegisteredForProver(VerifierAddress, ProverAddress),
}
