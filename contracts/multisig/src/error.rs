use cosmwasm_std::{StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("No active key found for {key_id:?}")]
    NoActiveKeyFound { key_id: String },

    #[error("{signer:?} already submitted a signature for signing session {session_id:?}")]
    DuplicateSignature { session_id: Uint64, signer: String },

    #[error("{signer:?} is not a participant in signing session {session_id:?}")]
    NotAParticipant { session_id: Uint64, signer: String },

    #[error("Signature verification failed: {reason:?}")]
    SignatureVerificationFailed { reason: String },

    #[error("{signer:?} submitted an invalid signature for signing session {session_id:?}")]
    InvalidSignature { session_id: Uint64, signer: String },

    #[error("Invalid public key format: {reason:?}")]
    InvalidPublicKeyFormat { reason: String },

    #[error("Invalid message format: {reason:?}")]
    InvalidMessageFormat { reason: String },

    #[error("Invalid signature format: {reason:?}")]
    InvalidSignatureFormat { reason: String },

    #[error("Signing session {session_id:?} is already closed")]
    SigningSessionClosed { session_id: Uint64 },

    #[error("Signing session {session_id:?} not found")]
    SigningSessionNotFound { session_id: Uint64 },

    #[error("Key ID {key_id:?} already exists")]
    DuplicateKeyID { key_id: String },

    #[error("number of participants does not match number of public keys")]
    PublicKeysMismatchParticipants,

    #[error("missing public key for participant {participant}")]
    MissingPublicKey { participant: String },

    #[error("key type mismatch")]
    KeyTypeMismatch,
}
