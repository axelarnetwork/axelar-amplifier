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
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use thiserror::Error;

use crate::Snapshot;

#[cw_serde]
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

impl FromStr for PollID {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str(s)?))
    }
}

pub trait Poll {
    // errors if the poll is not finished
    fn tally() -> Result<PollResult, Error>;
    // errors if sender is not a participant, if sender already voted, if the poll is finished or
    // if the number of votes doesn't match the poll size
    fn cast_vote(sender: Addr, poll_id: PollID, votes: Vec<bool>) -> Result<PollStatus, Error>;
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

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {}

#[cw_serde]
pub struct WeightedPoll {
    pub poll_id: PollID,
    pub snapshot: Snapshot,
    pub expires_at: u64,
    pub poll_size: usize,
    pub votes: Vec<Uint256>, // running tally of weighted votes
    pub status: PollStatus,
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
        }
    }
}

impl Poll for WeightedPoll {
    fn tally() -> Result<PollResult, Error> {
        todo!()
    }

    fn cast_vote(_sender: Addr, _poll_id: PollID, _votes: Vec<bool>) -> Result<PollStatus, Error> {
        todo!()
    }
}
