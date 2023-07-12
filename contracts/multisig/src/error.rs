use cosmwasm_std::{StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("No active key found for {key_id:?}")]
    NoActiveKeyFound { key_id: String },

    #[error("{signer:?} already submitted a signature for signing session {sig_id:?}")]
    DuplicateSignature { sig_id: Uint64, signer: String },

    #[error("{signer:?} is not a participant in signing session {sig_id:?}")]
    NotAParticipant { sig_id: Uint64, signer: String },

    #[error("Signature verification failed: {reason:?}")]
    SignatureVerificationFailed { reason: String },

    #[error("{signer:?} submitted an invalid signature for signing session {sig_id:?}")]
    InvalidSignature { sig_id: Uint64, signer: String },

    #[error("Invalid public key format: {reason:?}")]
    InvalidPublicKeyFormat { reason: String },

    #[error("Invalid message format: {reason:?}")]
    InvalidMessageFormat { reason: String },

    #[error("Invalid signature format: {reason:?}")]
    InvalidSignatureFormat { reason: String },

    #[error("Signing session {sig_id:?} is already closed")]
    SigningSessionClosed { sig_id: Uint64 },

    #[error("Signing session {sig_id:?} not found")]
    SigningSessionNotFound { sig_id: Uint64 },
}
