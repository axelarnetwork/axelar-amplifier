use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{Addr, StdError};
use cw2::VersionError;
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Version(#[from] VersionError),

    #[error("caller not unauthorized to perform this action")]
    Unauthorized,

    #[error("failed to obtain verifier details")]
    FailedToGetVerifierDetails,

    #[error("failed to get provers of verifier")]
    FailedToGetProversForVerifier,

    #[error("failed to migrate contract state")]
    Migration,

    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),

    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),

    #[error("gateway {0} is not registered")]
    GatewayNotRegistered(Addr),

    #[error("verifier {0} is not registered")]
    VerifierNotRegistered(Addr),
}
