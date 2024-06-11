use axelar_wasm_std::nonempty;
use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("caller is not authorized")]
    Unauthorized,

    #[error("message is invalid: {reason}")]
    InvalidMessage { reason: String },

    #[error("public key is invalid: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("signature is invalid: {reason}")]
    InvalidSignature { reason: String },

    #[error("chain name is invalid")]
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

    /// Todo, Below error throws: binary operation `==` cannot be applied to type `EncodingError<1024>`
    /// this is a workaround.
    #[error("encoding/decoding failure: [0]")]
    RkyvEncodingError(String),

    #[error("verifier set has not changed sufficiently since last update")]
    VerifierSetUnchanged,

    #[error("verifier set not confirmed")]
    VerifierSetNotConfirmed,

    #[error("a verifier set confirmation already in progress")]
    VerifierSetConfirmationInProgress,

    #[error("no verifier set stored")]
    NoVerifierSet,

    #[error("failed to serialize the response")]
    SerializeResponse,
}
