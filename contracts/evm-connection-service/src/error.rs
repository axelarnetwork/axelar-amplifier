use cosmwasm_std::{Addr, StdError};
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
}
