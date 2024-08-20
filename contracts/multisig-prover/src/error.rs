use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::StdError;
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("message is invalid")]
    InvalidMessage,

    #[error("public key is invalid: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("signature is invalid: {reason}")]
    InvalidSignature { reason: String },

    #[error("chain name is invalid")]
    #[deprecated(since = "0.6.0")]
    InvalidChainName,

    #[error("invalid participants: {reason}")]
    InvalidParticipants { reason: String },

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },

    #[error("public key not found for participant {participant}")]
    PublicKeyNotFound { participant: String },

    #[error(transparent)]
    ServiceRegistryError(#[from] service_registry::ContractError),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error(transparent)]
    BcsError(#[from] bcs::Error),

    #[error("verifier set has not changed sufficiently since last update")]
    VerifierSetUnchanged,

    #[error("verifier set not confirmed")]
    VerifierSetNotConfirmed,

    #[error("a verifier set confirmation already in progress")]
    VerifierSetConfirmationInProgress,

    #[error("no verifier set to confirm")]
    NoVerifierSetToConfirm,

    #[error("no verifier set stored")]
    NoVerifierSet,

    #[error("failed to serialize the response")]
    SerializeResponse,

    #[error("failed to create proof")]
    Proof,

    #[error("invalid verifier set")]
    InvalidVerifierSet,

    #[error("not enough verifiers")]
    NotEnoughVerifiers,

    #[error("invalid destination chain '{actual}', expected '{expected}'")]
    InvalidDestinationChain {
        actual: ChainName,
        expected: ChainName,
    },

    #[error("payload does not match the stored value")]
    PayloadMismatch,

    #[error("failed to serialize data for the external gateway")]
    SerializeData,
}
