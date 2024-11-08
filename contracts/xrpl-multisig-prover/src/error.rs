use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::StdError;
use thiserror::Error;
use router_api::ChainName;
use xrpl_types::error::XRPLError;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("failed to serialize")]
    FailedToSerialize,

    #[error("failed to update admin")]
    FailedToUpdateAdmin,

    #[error("invalid amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("invalid blob length")]
    InvalidBlobLength,

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },

    #[error("invalid destination address")]
    InvalidDestinationAddress,

    #[error("invalid destination chain '{actual}', expected '{expected}'")]
    InvalidDestinationChain {
        actual: ChainName,
        expected: ChainName,
    },

    #[error("invalid message ID {0}")]
    InvalidMessageId(String),

    #[error("invalid payload")]
    InvalidPayload,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid transaction ID {0}")]
    InvalidTxId(String),

    #[error("failed to fetch message status")]
    MessageStatusNotFound,

    #[error("no available tickets")]
    NoAvailableTickets,

    #[error("no verifier set stored")]
    NoVerifierSet,

    #[error("no verifier set to confirm")]
    NoVerifierSetToConfirm,

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error("not enough verifiers")]
    NotEnoughVerifiers,

    #[error("overflow error")]
    Overflow,

    #[error("payload hash mismatch")]
    PayloadHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("payment already has active signing session with ID {0}")]
    PaymentAlreadyHasActiveSigningSession(u64),

    #[error("payment already has completed signing session with ID {0}")]
    PaymentAlreadyHasCompletedSigningSession(u64),

    #[error("failed to serialize the response")]
    SerializeResponse,

    #[error("signature not found")]
    SignatureNotFound,

    #[error("confirmed SignerListSet transaction does not match expected verifier set")]
    SignerListMismatch,

    #[error(transparent)]
    Std(#[from] StdError),

    #[error("ticket count threshold has not been reached")]
    TicketCountThresholdNotReached,

    #[error("too many verifiers")]
    TooManyVerifiers,

    #[error("transaction status is already updated")]
    TxStatusAlreadyUpdated,

    #[error("transaction status is not pending")]
    TxStatusNotPending,

    #[error("a verifier set confirmation already in progress")]
    VerifierSetConfirmationInProgress,

    #[error("verifier set has not changed sufficiently since last update")]
    VerifierSetUnchanged,

    #[error(transparent)]
    XRPLTypeConversionError(#[from] XRPLError),
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
