use cosmwasm_std::{StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("No active key found for {owner:?}")]
    NoActiveKeyFound { owner: String },

    #[error("{signer:?} already submitted a signature for signing session {sig_id:?}")]
    DuplicateSignature { sig_id: Uint64, signer: String },

    #[error("{signer:?} is not a participant in signing session {sig_id:?}")]
    NotAParticipant { sig_id: Uint64, signer: String },

    #[error("{signer:?} submitted an invalid signature for signing session {sig_id:?}")]
    InvalidSignature { sig_id: Uint64, signer: String },

    #[error("Invalid public key format: {context:?}")]
    InvalidPublicKeyFormat { context: String },

    #[error("Invalid message format: {context:?}")]
    InvalidMessageFormat { context: String },

    #[error("Invalid signature format: {context:?}")]
    InvalidSignatureFormat { context: String },

    #[error("Signing session {sig_id:?} is already closed")]
    SigningSessionClosed { sig_id: Uint64 },

    #[error("Signing session {sig_id:?} not found")]
    SigningSessionNotFound { sig_id: Uint64 },
}
