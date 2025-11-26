use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::StdError;
use cw_utils::ParseReplyError;
use router_api::ChainName;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    ParseReply(#[from] ParseReplyError),

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
    ServiceRegistryError(#[from] service_registry_api::error::ContractError),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error(transparent)]
    BcsError(#[from] bcs::Error),

    // NOTE: using string "reason" because the `axelar_solana_encoding::error::Error` does not implement PartialEq
    #[error("Solana encoding/decoding error: [0]")]
    SolanaEncoding { reason: String },

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

    #[error("failed to get outgoing messages from gateway")]
    FailedToGetMessages,

    #[error("failed to build verifier set")]
    FailedToBuildVerifierSet,

    #[error("failed to check verifier set verification status")]
    FailedToVerifyVerifierSet,

    #[error("failed to update admin")]
    FailedToUpdateAdmin,

    #[error("failed to create wasm execute msg")]
    FailedToCreateWasmExecuteMsg,

    // Generic error to wrap cw_storage_plus errors
    // This should only be used for things that shouldn't happen, such as encountering
    // an error when loading data that should always load successfully.
    #[error("storage error")]
    StorageError,

    #[error("encoder is not implemented")]
    EncoderNotImplemented,
}
