use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

use crate::primitives::BondingState;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Overflow(#[from] OverflowError),
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
    #[error("Verifiers count exceeds u16 limit")]
    AuthorizedVerifiersExceedu16,
    #[error("Verifiers count is negative")]
    AuthorizedVerifiersNegative,
    #[error("max verifiers limit {0} exceeded by {1} verifiers")]
    VerifierLimitExceed(u16, u16),
    #[error("max verifiers limit {0} is below current authorized verifiers {1}")]
    MaxVerifiersSetBelowCurrent(u16, u16),
    #[error("unauthorized")]
    Unauthorized,
    #[error("service name already exists")]
    ServiceAlreadyExists,
    #[error("service not found")]
    ServiceNotFound,
    #[error("service override not found")]
    ServiceOverrideNotFound,
    #[error("verifier already authorized")]
    VerifierAlreadyAuthorized,
    #[error("funds are in the wrong denomination")]
    WrongDenom,
    #[error("verifier not found")]
    VerifierNotFound,
    #[error("invalid bonding state `{0:?}` for this operation")]
    InvalidBondingState(BondingState),
    #[error("no attached funds to bond")]
    NoFundsToBond,
    #[error("not enough verifiers")]
    NotEnoughVerifiers,
    #[error("verifier is jailed")]
    VerifierJailed,
    #[error("failed to unbond verifier")]
    FailedToUnbondVerifier,

    // Generic error to wrap cw_storage_plus errors
    // This should only be used for things that shouldn't happen, such as encountering
    // an error when loading data that should load successfully. For errors that can
    // happen in the normal course of things, use a more descriptive error
    #[error("storage error")]
    StorageError,
}
