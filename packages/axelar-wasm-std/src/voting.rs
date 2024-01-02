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
use std::collections::BTreeMap;
use std::fmt;
use std::ops::AddAssign;
use std::ops::Mul;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult, Uint256, Uint64};
use cw_storage_plus::{IntKey, Key, KeyDeserialize, PrimaryKey};
use num_traits::One;
use strum::EnumIter;
use strum::EnumString;
use strum::IntoEnumIterator;
use thiserror::Error;
use valuable::Valuable;

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

    #[error("message index out of bounds")]
    MessageIndexOutOfBounds,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct PollId(Uint64);

impl From<PollId> for String {
    fn from(val: PollId) -> Self {
        val.0.to_string()
    }
}

impl From<u64> for PollId {
    fn from(value: u64) -> Self {
        PollId(value.into())
    }
}
impl From<Uint64> for PollId {
    fn from(value: Uint64) -> Self {
        PollId(value)
    }
}

impl FromStr for PollId {
    type Err = StdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uint64::try_from(s)?))
    }
}

impl Mul for PollId {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl One for PollId {
    fn one() -> Self {
        PollId(Uint64::one())
    }
}

impl AddAssign for PollId {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl<'a> PrimaryKey<'a> for PollId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Val64(self.0.to_be_bytes())]
    }
}

impl KeyDeserialize for PollId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let id =
            Uint64::new(u64::from_cw_bytes(value.as_slice().try_into().map_err(
                |err: TryFromSliceError| StdError::generic_err(err.to_string()),
            )?));
        Ok(Self(id))
    }
}

impl fmt::Display for PollId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cw_serde]
#[derive(Eq, Hash, Ord, PartialOrd, EnumIter, EnumString, Valuable)]
pub enum Vote {
    SucceededOnChain, // the txn was included on chain, and achieved the intended result
    FailedOnChain,    // the txn was included on chain, but failed to achieve the intended result
    NotFound,         // the txn could not be found on chain in any blocks at the time of voting
}

impl fmt::Display for Vote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Vote::SucceededOnChain => write!(f, "SucceededOnChain"),
            Vote::FailedOnChain => write!(f, "FailedOnChain"),
            Vote::NotFound => write!(f, "NotFound"),
        }
    }
}

// Deserialization of enums as map keys is not supported by serde-json-wasm, we use String instead
#[cw_serde]
pub struct Tallies(BTreeMap<String, Uint256>);

impl Default for Tallies {
    fn default() -> Self {
        Self(
            Vote::iter()
                .map(|vote| (vote.to_string(), Uint256::zero()))
                .collect(),
        )
    }
}

impl Tallies {
    pub fn consensus(&self, quorum: Uint256) -> Option<Vote> {
        self.0.iter().find_map(|(vote, tally)| {
            if *tally >= quorum {
                Some(vote.parse().expect("can't parse vote string back to enum"))
            } else {
                None
            }
        })
    }

    pub fn tally(&mut self, vote: &Vote, weight: &Uint256) {
        *self
            .0
            .get_mut(&vote.to_string())
            .unwrap_or(&mut Uint256::zero()) += weight;
    }
}

#[cw_serde]
pub struct PollState {
    pub poll_id: PollId,
    pub results: Vec<Option<Vote>>,
    /// List of participants who voted for the winning result
    pub consensus_participants: Vec<String>,
}

#[cw_serde]
pub enum PollStatus {
    InProgress,
    Finished,
}

#[cw_serde]
pub struct Participation {
    pub weight: nonempty::Uint256,
    pub vote: Option<Vec<Vote>>,
}

#[cw_serde]
pub struct WeightedPoll {
    pub poll_id: PollId,
    pub quorum: nonempty::Uint256,
    pub expires_at: u64,
    pub poll_size: u64,
    pub tallies: Vec<Tallies>, // running tally of weighted votes
    pub status: PollStatus,
    pub participation: BTreeMap<String, Participation>,
}

impl WeightedPoll {
    pub fn new(poll_id: PollId, snapshot: Snapshot, expiry: u64, poll_size: usize) -> Self {
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
                        vote: None,
                    },
                )
            })
            .collect();

        WeightedPoll {
            poll_id,
            quorum: snapshot.quorum,
            expires_at: expiry,
            poll_size: poll_size as u64,
            tallies: vec![Tallies::default(); poll_size],
            status: PollStatus::InProgress,
            participation,
        }
    }

    pub fn finish(mut self, block_height: u64) -> Result<Self, Error> {
        if matches!(self.status, PollStatus::Finished { .. }) {
            return Err(Error::PollNotInProgress);
        }

        if block_height < self.expires_at {
            return Err(Error::PollNotEnded);
        }

        self.status = PollStatus::Finished;

        Ok(self)
    }

    pub fn state(&self) -> PollState {
        let quorum: Uint256 = self.quorum.into();
        let results: Vec<Option<Vote>> = self
            .tallies
            .iter()
            .map(|tallies| tallies.consensus(quorum))
            .collect();

        let consensus_participants = self
            .participation
            .iter()
            .filter_map(|(address, participation)| {
                participation.vote.as_ref().and_then(|votes| {
                    let voted_consensus = votes.iter().zip(results.iter()).all(|(vote, result)| {
                        result.is_none() || Some(vote) == result.as_ref() // if there was no consensus, we don't care about the vote
                    });

                    if voted_consensus {
                        Some(address.to_owned())
                    } else {
                        None
                    }
                })
            })
            .collect();

        PollState {
            poll_id: self.poll_id,
            results,
            consensus_participants,
        }
    }

    pub fn consensus(&self, idx: u32) -> Result<Option<Vote>, Error> {
        Ok(self
            .tallies
            .get(idx as usize)
            .ok_or(Error::MessageIndexOutOfBounds)?
            .consensus(self.quorum.into()))
    }

    pub fn cast_vote(
        mut self,
        block_height: u64,
        sender: &Addr,
        votes: Vec<Vote>,
    ) -> Result<Self, Error> {
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

        if participation.vote.is_some() {
            return Err(Error::AlreadyVoted);
        }

        self.tallies
            .iter_mut()
            .zip(votes.iter())
            .for_each(|(tallies, vote)| {
                tallies.tally(vote, &participation.weight.into());
            });

        participation.vote = Some(votes);

        Ok(self)
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
        let poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];

        assert_eq!(
            poll.participation.get("addr1").unwrap(),
            &Participation {
                weight: nonempty::Uint256::try_from(Uint256::from(100u64)).unwrap(),
                vote: None,
            }
        );

        let poll = poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .unwrap();

        assert_eq!(
            poll.participation.get("addr1").unwrap(),
            &Participation {
                weight: nonempty::Uint256::try_from(Uint256::from(100u64)).unwrap(),
                vote: Some(votes),
            }
        );
    }

    #[test]
    fn voter_not_a_participant() {
        let mut rng = thread_rng();
        let poll = new_poll(
            rng.gen::<u64>(),
            rng.gen_range(1..50),
            vec!["addr1", "addr2"],
        );
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];

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
        let poll = new_poll(
            1,
            rand::thread_rng().gen_range(1..50),
            vec!["addr1", "addr2"],
        );
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];
        assert_eq!(
            poll.cast_vote(2, &Addr::unchecked("addr1"), votes),
            Err(Error::PollExpired)
        );
    }

    #[test]
    fn vote_size_is_invalid() {
        let poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![Vote::SucceededOnChain];
        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked("addr1"), votes),
            Err(Error::InvalidVoteSize)
        );
    }

    #[test]
    fn voter_already_voted() {
        let poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];

        let poll = poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .unwrap();
        assert_eq!(
            poll.cast_vote(1, &Addr::unchecked("addr1"), votes),
            Err(Error::AlreadyVoted)
        );
    }

    #[test]
    fn finish_before_poll_expiry() {
        let poll = new_poll(1, 2, vec!["addr1", "addr2"]);
        assert_eq!(poll.finish(0), Err(Error::PollNotEnded));
    }

    #[test]
    fn finish_after_poll_conclude() {
        let mut poll = new_poll(2, 2, vec!["addr1", "addr2"]);
        poll.status = PollStatus::Finished;
        assert_eq!(poll.finish(2), Err(Error::PollNotInProgress));
    }

    #[test]
    fn should_conclude_poll() {
        let poll = new_poll(2, 2, vec!["addr1", "addr2", "addr3"]);
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];

        let poll = poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .unwrap()
            .cast_vote(1, &Addr::unchecked("addr2"), votes)
            .unwrap();

        let poll = poll.finish(2).unwrap();
        assert_eq!(poll.status, PollStatus::Finished);

        let result = poll.state();
        assert_eq!(
            result,
            PollState {
                poll_id: PollId::from(Uint64::one()),
                results: vec![Some(Vote::SucceededOnChain), Some(Vote::SucceededOnChain)],
                consensus_participants: vec!["addr1".to_string(), "addr2".to_string(),],
            }
        );
    }

    #[test]
    fn result_filters_non_consensus_voters() {
        let poll = new_poll(2, 2, vec!["addr1", "addr2", "addr3"]);
        let votes = vec![Vote::SucceededOnChain, Vote::SucceededOnChain];
        let wrong_votes = vec![Vote::FailedOnChain, Vote::FailedOnChain];

        let poll = poll
            .cast_vote(1, &Addr::unchecked("addr1"), votes.clone())
            .unwrap()
            .cast_vote(1, &Addr::unchecked("addr2"), wrong_votes)
            .unwrap()
            .cast_vote(1, &Addr::unchecked("addr3"), votes)
            .unwrap();

        let result = poll.finish(2).unwrap().state();

        assert_eq!(
            result,
            PollState {
                poll_id: PollId::from(Uint64::one()),
                results: vec![Some(Vote::SucceededOnChain), Some(Vote::SucceededOnChain)],
                consensus_participants: vec!["addr1".to_string(), "addr3".to_string(),],
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

        let snapshot = Snapshot::new(threshold.try_into().unwrap(), participants);

        WeightedPoll::new(PollId::from(Uint64::one()), snapshot, expires_at, poll_size)
    }
}
