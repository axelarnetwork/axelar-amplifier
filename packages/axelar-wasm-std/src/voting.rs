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

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut};

use crate::Snapshot;

use thiserror::Error;

#[cw_serde]
pub struct PollID(String);

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

pub fn start_poll(
    _deps: DepsMut,
    _snapshot: Snapshot,
    _block_height_expiry: Option<u64>,
    _poll_size: usize, // number of items in the poll to be voted on
) -> Result<PollID, Error> {
    todo!()
}

// errors if the poll is not finished
pub fn tally_results(_deps: DepsMut, _poll_id: PollID) -> Result<PollResult, Error> {
    todo!()
}

// errors if sender is not a participant, if sender already voted, if poll doesn't exist, if the poll is finished or
// if the number of votes doesn't match the poll size
pub fn cast_vote(
    _deps: DepsMut,
    _sender: Addr,
    _poll_id: PollID,
    _votes: Vec<bool>,
) -> Result<PollStatus, Error> {
    todo!()
}
