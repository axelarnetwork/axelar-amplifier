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

    #[error("worker set has not changed sufficiently since last update")]
    WorkerSetUnchanged,

    #[error("worker set not confirmed")]
    WorkerSetNotConfirmed,

    #[error("a worker set confirmation already in progress")]
    WorkerSetConfirmationInProgress,
}
