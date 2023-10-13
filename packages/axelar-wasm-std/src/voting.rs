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
use std::collections::HashMap;
use std::fmt;
use std::ops::AddAssign;
use std::ops::Mul;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult, Uint256, Uint64};
use cw_storage_plus::{IntKey, Key, KeyDeserialize, PrimaryKey};
use num_traits::One;
use thiserror::Error;

use crate::nonempty;
use crate::Snapshot;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("not a participant")]
    NotParticipant,

    #[error("invalid vote size")]
    InvalidVoteSize,

    #[error("already voted")]
    AlreadyVoted,

    #[error("poll is not in progress")]
    PollNotInProgress,

    #[error("cannot tally before poll end")]
    PollNotEnded,

    #[error("poll has expired")]
    PollExpired,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct PollID(Uint64);

impl From<PollID> for String {
    fn from(val: PollID) -> Self {
        val.0.to_string()
    }
}

impl From<u64> for PollID {
    fn from(value: u64) -> Self {
        PollID(value.into())
    }
}
impl From<Uint64> for PollID {
    fn from(value: Uint64) -> Self {
        PollID(value)
    }
}

impl FromStr for PollID {
    type Err = StdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uint64::try_from(s)?))
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
        PollID(Uint64::one())
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
        vec![Key::Val64(self.0.to_be_bytes())]
    }
}

impl KeyDeserialize for PollID {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let id =
            Uint64::new(u64::from_cw_bytes(value.as_slice().try_into().map_err(
                |err: TryFromSliceError| StdError::generic_err(err.to_string()),
            )?));
        Ok(Self(id))
    }
}

impl fmt::Display for PollID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
        votes: Vec<bool>,
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
pub struct Participation {
    pub weight: nonempty::Uint256,
    pub voted: bool,
}

#[cw_serde]
pub struct WeightedPoll {
    poll_id: PollID,
    quorum: nonempty::Uint256,
    expires_at: u64,
    poll_size: u64,
    votes: Vec<Uint256>, // running tally of weighted votes
    status: PollStatus,
    participation: HashMap<String, Participation>,
}

impl WeightedPoll {
    pub fn new(poll_id: PollID, snapshot: Snapshot, expiry: u64, poll_size: usize) -> Self {
        // initialize the map with all possible voters so it always have the same size and therefore
        // all voters will use roughly the same amount of gas when casting a vote.
        let participation = snapshot
            .participants
            .into_iter()
            .map(|(address, participant)| {
                (
                    address,
                    Participation {
                        weight: participant.weight,
                        voted: false,
                    },
                )
            })
            .collect();

        WeightedPoll {
            poll_id,
            quorum: snapshot.quorum,
            expires_at: expiry,
            poll_size: poll_size as u64,
            votes: vec![Uint256::zero(); poll_size],
            status: PollStatus::InProgress,
            participation,
        }
    }
}

impl Poll for WeightedPoll {
    fn tally(&mut self, block_height: u64) -> Result<PollResult, Error> {
        let everyone_voted = self
            .participation
            .iter()
            .all(|(_, participation)| participation.voted);

        if block_height < self.expires_at
            // can tally early if all participants voted
            && !everyone_voted
        {
            return Err(Error::PollNotEnded);
        }

        if self.status == PollStatus::Finished {
            return Err(Error::PollNotInProgress);
        }

        self.status = PollStatus::Finished;

        Ok(PollResult {
            poll_id: self.poll_id,
            results: self
                .votes
                .iter()
                .map(|tally| *tally >= self.quorum.into())
                .collect(),
        })
    }

    fn cast_vote(
        &mut self,
        block_height: u64,
        sender: &Addr,
        votes: Vec<bool>,
    ) -> Result<PollStatus, Error> {
        let participation = self
            .participation
            .get_mut(sender.as_str())
            .ok_or(Error::NotParticipant)?;

        if block_height >= self.expires_at {
            return Err(Error::PollExpired);
        }

        if votes.len() != self.poll_size as usize {
            return Err(Error::InvalidVoteSize);
        }

        if participation.voted {
            return Err(Error::AlreadyVoted);
        }

        if self.status != PollStatus::InProgress {
            return Err(Error::PollNotInProgress);
        }

        participation.voted = true;

        self.votes
            .iter_mut()
            .zip(votes.into_iter())
            .filter(|(_, vote)| *vote)
            .for_each(|(tally, _)| {
                *tally += Uint256::from(participation.weight);
            });

        Ok(PollStatus::InProgress)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Addr, Uint256, Uint64};
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use crate::{nonempty, Participant, Threshold};

    use super::*;

    #[test]
    fn cast_vote() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![true, true];

        assert_eq!(
            poll.participation.get("addr1").unwrap(),
            &Participation {
                weight: nonempty::Uint256::try_from(Uint256::from(100u64)).unwrap(),
                voted: false,
            }
        );

        assert!(poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .is_ok());

        assert_eq!(
            poll.participation.get("addr1").unwrap(),
            &Participation {
                weight: nonempty::Uint256::try_from(Uint256::from(100u64)).unwrap(),
                voted: true,
            }
        );
    }

    #[test]
    fn voter_not_a_participant() {
        let mut rng = thread_rng();
        let mut poll = new_poll(
            rng.gen::<u64>(),
            rng.gen_range(1..50),
            vec!["addr1", "addr2"],
        );
        let votes = vec![true, true];

        let rand_addr: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked(rand_addr.as_str()), votes),
            Err(Error::NotParticipant)
        );
    }

    #[test]
    fn poll_expired() {
        let mut poll = new_poll(
            1,
            rand::thread_rng().gen_range(1..50),
            vec!["addr1", "addr2"],
        );
        let votes = vec![true, true];
        assert_eq!(
            poll.cast_vote(2, &Addr::unchecked("addr1"), votes),
            Err(Error::PollExpired)
        );
    }

    #[test]
    fn vote_size_is_invalid() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![true];
        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked("addr1"), votes),
            Err(Error::InvalidVoteSize)
        );
    }

    #[test]
    fn voter_already_voted() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![true, true];

        assert!(poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .is_ok());
        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked("addr1"), votes),
            Err(Error::AlreadyVoted)
        );
    }

    #[test]
    fn poll_is_not_in_progress() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![true, true];
        poll.status = PollStatus::Finished;
        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked("addr1"), votes),
            Err(Error::PollNotInProgress)
        );
    }

    #[test]
    fn tally_before_poll_end() {
        let mut poll = new_poll(1, 2, vec!["addr1", "addr2"]);
        assert_eq!(poll.tally(0), Err(Error::PollNotEnded));
    }

    #[test]
    fn tally_after_poll_conclude() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        poll.status = PollStatus::Finished;
        assert_eq!(poll.tally(2), Err(Error::PollNotInProgress));
    }

    #[test]
    fn should_conclude_poll() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2", "addr3"]);
        let votes = vec![true, true];

        assert!(poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .is_ok());
        assert!(poll.cast_vote(1, &Addr::unchecked("addr2"), votes).is_ok());

        let result = poll.tally(2).unwrap();
        assert_eq!(poll.status, PollStatus::Finished);

        assert_eq!(
            result,
            PollResult {
                poll_id: PollID::from(Uint64::one()),
                results: vec![true, true],
            }
        );
    }

    fn new_poll(expires_at: u64, poll_size: usize, participants: Vec<&str>) -> WeightedPoll {
        let participants: nonempty::Vec<Participant> = participants
            .into_iter()
            .map(|participant| Participant {
                address: Addr::unchecked(participant),
                weight: nonempty::Uint256::try_from(Uint256::from_u128(100)).unwrap(),
            })
            .collect::<Vec<Participant>>()
            .try_into()
            .unwrap();

        let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
        let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
        let threshold: Threshold = (numerator, denominator).try_into().unwrap();

        let snapshot = Snapshot::new(threshold, participants);

        WeightedPoll::new(PollID::from(Uint64::one()), snapshot, expires_at, poll_size)
    }
}
