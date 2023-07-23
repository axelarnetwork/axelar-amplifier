/*
   Module for creating polls, handling votes and getting the result of polls.
   A poll represents a list of 1 or more items to be voted on.
   For each item in the poll, the final result can be either true or false.
   This module is agnostic to the actual items in the poll. It is up to the
   users of this module to determine the meaning of a poll.

   Example:
   A contract wishes to verify a list of transactions occurred on an external chain via RPC voting.
   The contract starts a poll via start_poll, which returns a PollID. The contract maps the PollID
   to the list of messages in the poll. Participants vote on the validity of the transactions via
   cast_vote. Once everyone has voted, the contract calls tally_results to get the results of the poll.
   The contract then processes the results and takes appropriate action for each transaction, depending
   on whether or not the transaction was successfully verified.
*/
use std::array::TryFromSliceError;
use std::ops::AddAssign;
use std::ops::Mul;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult, Uint256};
use cw_storage_plus::{IntKey, Key, KeyDeserialize, PrimaryKey};
use num_traits::One;
use thiserror::Error;

use crate::Snapshot;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("not participant")]
    NotParticipant(),

    #[error("invalid vote size")]
    InvalidVoteSize(),

    #[error("already voted")]
    AlreadyVoted(),

    #[error("poll not in progress")]
    PollNotInProgress(),

    #[error("cannot tally before poll end")]
    PollNotEnded(),

    #[error("poll expired")]
    PollExpired(),
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct PollID(u64);

impl From<PollID> for String {
    fn from(val: PollID) -> Self {
        val.0.to_string()
    }
}

impl From<u64> for PollID {
    fn from(value: u64) -> Self {
        PollID(value)
    }
}

impl Mul for PollID {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl One for PollID {
    fn one() -> Self {
        PollID(1)
    }
}

impl AddAssign for PollID {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl<'a> PrimaryKey<'a> for PollID {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Val64(self.0.to_cw_bytes())]
    }
}

impl KeyDeserialize for PollID {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let id = u64::from_cw_bytes(
            value
                .as_slice()
                .try_into()
                .map_err(|err: TryFromSliceError| StdError::generic_err(err.to_string()))?,
        );
        Ok(Self(id))
    }
}

pub trait Poll {
    // errors if the poll is not finished
    fn tally(&mut self, block_height: u64) -> Result<PollResult, Error>;
    // errors if sender is not a participant, if sender already voted, if the poll is finished or
    // if the number of votes doesn't match the poll size
    fn cast_vote(
        &mut self,
        block_height: u64,
        sender: &Addr,
        votes: &[bool],
    ) -> Result<PollStatus, Error>;
}

#[cw_serde]
pub struct PollResult {
    pub poll_id: PollID,
    pub results: Vec<bool>,
}

#[cw_serde]
pub enum PollStatus {
    InProgress,
    Finished,
}

#[cw_serde]
pub struct WeightedPoll {
    poll_id: PollID,
    snapshot: Snapshot,
    expires_at: u64,
    poll_size: usize,
    votes: Vec<Uint256>, // running tally of weighted votes
    status: PollStatus,
    voted: Vec<Addr>,
}

impl WeightedPoll {
    pub fn new(poll_id: PollID, snapshot: Snapshot, expiry: u64, poll_size: usize) -> Self {
        WeightedPoll {
            poll_id,
            snapshot,
            expires_at: expiry,
            poll_size,
            votes: vec![Uint256::zero(); poll_size],
            status: PollStatus::InProgress,
            voted: Vec::new(),
        }
    }
}

impl Poll for WeightedPoll {
    fn tally(&mut self, block_height: u64) -> Result<PollResult, Error> {
        if block_height < self.expires_at {
            return Err(Error::PollNotEnded {});
        }

        self.status = PollStatus::Finished;

        Ok(PollResult {
            poll_id: self.poll_id,
            results: self
                .votes
                .iter()
                .map(|v| *v > self.snapshot.quorum.into())
                .collect(),
        })
    }

    fn cast_vote(
        &mut self,
        block_height: u64,
        sender: &Addr,
        votes: &[bool],
    ) -> Result<PollStatus, Error> {
        if self.snapshot.is_participant(sender) {
            return Err(Error::NotParticipant {});
        }

        if block_height > self.expires_at {
            return Err(Error::PollExpired {});
        }

        if votes.len() != self.poll_size {
            return Err(Error::InvalidVoteSize {});
        }

        if self.voted.contains(sender) {
            return Err(Error::AlreadyVoted {});
        }

        if self.status != PollStatus::InProgress {
            return Err(Error::PollNotInProgress {});
        }

        votes.iter().enumerate().for_each(|(i, vote)| {
            if *vote {
                self.votes[i] += self.snapshot.get_participant_weight(sender).unwrap();
            }
        });

        for (tally, vote) in self.votes.iter_mut().zip(votes.iter()) {
            if *vote {
                *tally += self.snapshot.get_participant_weight(sender).unwrap();
            }
        }

        Ok(PollStatus::InProgress)
    }
}
