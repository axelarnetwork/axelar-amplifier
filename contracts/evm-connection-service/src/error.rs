use cosmwasm_std::{Addr, StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},
    #[error("Invalid request id")]
    InvalidRequestId {},
    #[error("Voting already closed")]
    VotingAlreadyClosed {},
    #[error("poll does not exist")]
    PollNonExistent {},
    #[error("Voter {voter:?} has already voted")]
    AlreadyVoted { voter: Addr },
    #[error("Address {voter:?} is not eligible to vote in this poll")]
    NotEligibleToVote { voter: Addr },
    #[error("Key {key:?} not found")]
    KeyNotFound { key: String },
    #[error("Key {key:?} is not activated yet")]
    KeyNotActive { key: String },
    #[error("Signing session {id:?} has expired")]
    ExpiredSigningSession { id: Uint64 },
    #[error("{signer:?} is not a participant of signing {id:?}")]
    NotEligibleToSign { signer: Addr, id: Uint64 },
    #[error("participant {signer:?} already submitted its signature for signing {id:?}")]
    AlreadySigned { signer: Addr, id: Uint64 },
    #[error("Invalid signature received from participant {signer:?} for signing {id:?}")]
    InvalidSignature { signer: Addr, id: Uint64 },
    #[error("Signing session {id:?} has closed")]
    SigningSessionClosed { id: Uint64 },
}
