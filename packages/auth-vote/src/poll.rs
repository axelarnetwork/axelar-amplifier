use std::fmt::Display;

use cosmwasm_std::{Addr, Binary, Order, Storage, Uint256, Uint64};
use snapshotter::snapshot::Snapshot;

use crate::{
    state::{is_voter_late_map, tallied_votes, Poll, PollState, TalliedVote, POLLS},
    utils::hash,
    AuthError, AuthVoting,
};

#[derive(PartialEq, Eq)]
pub enum VoteResult {
    NoVote,
    VoteInTime,
    VotedLate,
}

impl Display for VoteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteResult::NoVote => write!(f, "NoVote"),
            VoteResult::VoteInTime => write!(f, "VoteInTime"),
            VoteResult::VotedLate => write!(f, "VotedLate"),
        }
    }
}

impl<'a> Poll {
    pub fn new(id: Uint64, expires_at: Uint64, snapshot: Snapshot, message: Binary) -> Self {
        Self {
            id,
            expires_at,
            result: None,
            state: PollState::Pending,
            completed_at: None,
            snapshot,
            message,
        }
    }

    pub fn vote(
        &mut self,
        store: &mut dyn Storage,
        settings: &AuthVoting,
        voter: &Addr,
        block_height: u64,
        data: Binary,
    ) -> Result<VoteResult, AuthError> {
        if self.has_voted(store, voter) {
            return Err(AuthError::AlreadyVoted {
                voter: voter.to_owned(),
            });
        }

        if self
            .snapshot
            .get_participant_weight(&voter.clone().into_string())
            .is_zero()
        {
            return Err(AuthError::NotEligibleToVote {
                voter: voter.to_owned(),
            });
        }

        if self.is(PollState::Failed) {
            return Ok(VoteResult::NoVote);
        }

        if self.is(PollState::Completed) && self.is_in_grace_period(settings, block_height) {
            self.vote_late(store, voter, data)?;

            return Ok(VoteResult::VotedLate);
        }

        if self.is(PollState::Completed) {
            return Ok(VoteResult::NoVote);
        }

        self.vote_before_completion(store, settings, voter, block_height, data)?;

        Ok(VoteResult::VoteInTime)
    }

    fn has_voted(&self, store: &dyn Storage, voter: &Addr) -> bool {
        let result = self.get_tallied_votes(store).find(|item| {
            let (_, tallied_vote) = item.as_ref().unwrap();
            tallied_vote.is_voter_late_map().has(store, voter)
        });

        result.is_some()
    }

    fn vote_late(
        &mut self,
        store: &mut dyn Storage,
        voter: &Addr,
        data: Binary,
    ) -> Result<(), AuthError> {
        self.tally_vote(store, voter, data, true)?;

        Ok(())
    }

    fn vote_before_completion(
        &mut self,
        store: &mut dyn Storage,
        settings: &AuthVoting,
        voter: &Addr,
        block_height: u64,
        data: Binary,
    ) -> Result<(), AuthError> {
        self.tally_vote(store, voter, data, false)?;

        let majority_vote = self.get_majority_vote(store)?;

        let passing_weight = self
            .snapshot
            .calculate_min_passing_weight(&settings.voting_threshold);

        if self.has_enough_votes(store, settings, passing_weight, &majority_vote.tally) {
            self.result = Some(majority_vote.data);
            self.state = PollState::Completed;
            self.completed_at = Some(Uint64::from(block_height));

            POLLS.save(store, self.id.u64(), self)?;
        } else if self.cannot_win(store, passing_weight, &majority_vote.tally) {
            self.state = PollState::Failed;

            POLLS.save(store, self.id.u64(), self)?;
        }

        Ok(())
    }

    fn tally_vote(
        &mut self,
        store: &mut dyn Storage,
        voter: &Addr,
        data: Binary,
        is_late: bool,
    ) -> Result<(), AuthError> {
        let hash = hash(&data);
        let voting_power = self
            .snapshot
            .get_participant_weight(&voter.clone().into_string());

        let mut is_voter_late_namespace = String::new();

        tallied_votes().update(
            store,
            (self.id.u64(), hash),
            |v| -> Result<TalliedVote, AuthError> {
                match v {
                    Some(mut tallied_vote) => {
                        tallied_vote.tally += voting_power;
                        is_voter_late_namespace = tallied_vote.is_voter_late_namespace.clone();
                        Ok(tallied_vote)
                    }
                    None => Ok(TalliedVote::new(voting_power, data, self.id)),
                }
            },
        )?;

        is_voter_late_map(&is_voter_late_namespace)
            .save(store, voter, &is_late)
            .unwrap(); // TODO: this might need to be improved somehow

        Ok(())
    }

    fn has_enough_votes(
        &self,
        store: &dyn Storage,
        settings: &AuthVoting,
        passing_weight: Uint256,
        majority: &Uint256,
    ) -> bool {
        majority.ge(&passing_weight) && self.get_voter_count(store) >= settings.min_voter_count
    }

    fn cannot_win(
        &mut self,
        store: &dyn Storage,
        passing_weight: Uint256,
        majority: &Uint256,
    ) -> bool {
        let already_tallied = self.get_tallied_voting_power(store);
        let missing_voting_power = self.snapshot.get_participants_weight() - already_tallied;

        (*majority + missing_voting_power).lt(&passing_weight)
    }

    fn get_tallied_voting_power(&self, store: &dyn Storage) -> Uint256 {
        self.get_tallied_votes(store)
            .fold(Uint256::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum + tallied_vote.tally
            })
    }

    fn get_voter_count(&self, store: &dyn Storage) -> Uint64 {
        self.get_tallied_votes(store)
            .fold(Uint64::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum
                    + Uint64::from(
                        tallied_vote
                            .is_voter_late_map()
                            .keys(store, None, None, Order::Ascending)
                            .count() as u64,
                    )
            })
    }

    fn is_in_grace_period(&self, settings: &AuthVoting, block_height: u64) -> bool {
        block_height < self.completed_at.unwrap().u64() + settings.voting_grace_period.u64()
    }

    fn get_majority_vote(&self, store: &dyn Storage) -> Result<TalliedVote, AuthError> {
        let (_, majority) = self
            .get_tallied_votes(store)
            .reduce(|accum, item| {
                let (_, max_tallied_vote) = accum.as_ref().unwrap();
                let (_, tallied_vote) = item.as_ref().unwrap();
                if max_tallied_vote.tally > tallied_vote.tally {
                    accum
                } else {
                    item
                }
            })
            .unwrap()?;

        Ok(majority)
    }

    #[allow(clippy::type_complexity)]
    fn get_tallied_votes(
        &'a self,
        store: &'a dyn Storage,
    ) -> Box<(dyn Iterator<Item = Result<((u64, u64), TalliedVote), cosmwasm_std::StdError>> + '_)>
    {
        tallied_votes()
            .idx
            .poll_id
            .prefix(self.id.u64())
            .range(store, None, None, Order::Ascending)
    }

    fn is(&self, state: PollState) -> bool {
        self.state == state
    }
}
