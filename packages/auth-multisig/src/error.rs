use cosmwasm_std::{Addr, StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("NotActiveKey: No active key")]
    NotActiveKey {},
    #[error("KeyNotFound: Key {key:?} not found")]
    KeyNotFound { key: Uint64 },
    #[error("KeyNotActive: Key {key:?} is not activated yet")]
    KeyNotActive { key: Uint64 },
    #[error("ExpiredSigningSession: Signing session {id:?} has expired")]
    ExpiredSigningSession { id: Uint64 },
    #[error("NotEligibleToSign: {signer:?} is not a participant of signing {id:?}")]
    NotEligibleToSign { signer: Addr, id: Uint64 },
    #[error(
        "AlreadySigned: participant {signer:?} already submitted its signature for signing {id:?}"
    )]
    AlreadySigned { signer: Addr, id: Uint64 },
    #[error("InvalidSignature: Invalid signature received from participant {signer:?} for signing {id:?}")]
    InvalidSignature { signer: Addr, id: Uint64 },
    #[error("SigningSessionClosed: Signing session {id:?} has closed")]
    SigningSessionClosed { id: Uint64 },
}
