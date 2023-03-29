use cosmwasm_std::{Addr, StdError, Uint64};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("PollNonExistent: Poll {poll_id:?} does not exist")]
    PollNonExistent { poll_id: Uint64 },
    #[error("AlreadyVoted: Voter {voter:?} has already voted")]
    AlreadyVoted { voter: Addr },
    #[error("NotEligibleToVote: Address {voter:?} is not eligible to vote in this poll")]
    NotEligibleToVote { voter: Addr },
}
