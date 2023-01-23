use std::fmt::Display;

use cosmwasm_std::{Addr, Order, Storage, Uint256, Uint64};

use crate::{
    msg::ActionResponse,
    state::{
        is_voter_late_map, tallied_votes, PollMetadata, PollState, ServiceInfo, TalliedVote, POLLS,
    },
    utils::hash,
    ContractError,
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

pub struct Poll<'a> {
    pub metadata: PollMetadata,
    pub store: &'a mut dyn Storage,
    pub service_info: ServiceInfo,
    pub passing_weight: Uint256,
}

impl<'a> Poll<'a> {
    pub fn new(
        metadata: PollMetadata,
        store: &'a mut dyn Storage,
        service_info: ServiceInfo,
    ) -> Self {
        let passing_weight = metadata
            .snapshot
            .calculate_min_passing_weight(&service_info.voting_threshold);

        Self {
            metadata,
            store,
            service_info,
            passing_weight,
        }
    }

    pub fn vote(
        &mut self,
        voter: &Addr,
        block_height: u64,
        data: ActionResponse,
    ) -> Result<VoteResult, ContractError> {
        if self.is(PollState::NonExistent) {
            return Err(ContractError::PollNonExistent {});
        }

        if self.has_voted(voter) {
            return Err(ContractError::AlreadyVoted {
                voter: voter.to_owned(),
            });
        }

        if self
            .metadata
            .snapshot
            .get_participant_weight(self.store, voter)
            .is_zero()
        {
            return Err(ContractError::NotEligibleToVote {
                voter: voter.to_owned(),
            });
        }

        if self.is(PollState::Failed) {
            return Ok(VoteResult::NoVote);
        }

        if self.is(PollState::Completed) && self.is_in_grace_period(block_height) {
            self.vote_late(voter, data)?;

            return Ok(VoteResult::VotedLate);
        }

        if self.is(PollState::Completed) {
            return Ok(VoteResult::NoVote);
        }

        self.vote_before_completion(voter, block_height, data)?;

        Ok(VoteResult::VoteInTime)
    }

    fn has_voted(&self, voter: &Addr) -> bool {
        let result = self.get_tallied_votes().find(|item| {
            let (_, tallied_vote) = item.as_ref().unwrap();
            tallied_vote.is_voter_late_map().has(self.store, voter)
        });

        result.is_some()
    }

    fn vote_late(&mut self, voter: &Addr, data: ActionResponse) -> Result<(), ContractError> {
        self.tally_vote(voter, data, true)?;

        Ok(())
    }

    fn vote_before_completion(
        &mut self,
        voter: &Addr,
        block_height: u64,
        data: ActionResponse,
    ) -> Result<(), ContractError> {
        self.tally_vote(voter, data, false)?;

        let majority_vote = self.get_majority_vote()?;

        if self.has_enough_votes(&majority_vote.tally) {
            self.metadata.result = Some(majority_vote.data);
            self.metadata.state = PollState::Completed;
            self.metadata.completed_at = Some(Uint64::from(block_height));

            POLLS.save(self.store, self.metadata.id.u64(), &self.metadata)?;
        } else if self.cannot_win(&majority_vote.tally) {
            self.metadata.state = PollState::Failed;

            POLLS.save(self.store, self.metadata.id.u64(), &self.metadata)?;
        }

        Ok(())
    }

    fn tally_vote(
        &mut self,
        voter: &Addr,
        data: ActionResponse,
        is_late: bool,
    ) -> Result<(), ContractError> {
        let hash = hash(&data);
        let voting_power = self
            .metadata
            .snapshot
            .get_participant_weight(self.store, voter);

        let mut is_voter_late_namespace = String::new();

        tallied_votes().update(
            self.store,
            (self.metadata.id.u64(), hash),
            |v| -> Result<TalliedVote, ContractError> {
                match v {
                    Some(mut tallied_vote) => {
                        tallied_vote.tally += voting_power;
                        is_voter_late_namespace = tallied_vote.is_voter_late_namespace.clone();
                        Ok(tallied_vote)
                    }
                    None => Ok(TalliedVote::new(voting_power, data, self.metadata.id)),
                }
            },
        )?;

        is_voter_late_map(&is_voter_late_namespace)
            .save(self.store, voter, &is_late)
            .unwrap(); // TODO: this might need to be improved somehow

        Ok(())
    }

    fn has_enough_votes(&self, majority: &Uint256) -> bool {
        majority.ge(&self.passing_weight)
            && self.get_voter_count() >= self.service_info.min_voter_count
    }

    fn cannot_win(&mut self, majority: &Uint256) -> bool {
        let already_tallied = self.get_tallied_voting_power();
        let missing_voting_power =
            self.metadata.snapshot.get_participants_weight(self.store) - already_tallied;

        (*majority + missing_voting_power).lt(&self.passing_weight)
    }

    fn get_tallied_voting_power(&self) -> Uint256 {
        self.get_tallied_votes()
            .fold(Uint256::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum + tallied_vote.tally
            })
    }

    fn get_voter_count(&self) -> Uint64 {
        self.get_tallied_votes()
            .fold(Uint64::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum
                    + Uint64::from(
                        tallied_vote
                            .is_voter_late_map()
                            .keys(self.store, None, None, Order::Ascending)
                            .count() as u64,
                    )
            })
    }

    fn is_in_grace_period(&self, block_height: u64) -> bool {
        block_height
            < self.metadata.completed_at.unwrap().u64()
                + self.service_info.voting_grace_period.u64()
    }

    fn get_majority_vote(&self) -> Result<TalliedVote, ContractError> {
        let (_, majority) = self
            .get_tallied_votes()
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
        &self,
    ) -> Box<(dyn Iterator<Item = Result<((u64, u64), TalliedVote), cosmwasm_std::StdError>> + '_)>
    {
        tallied_votes()
            .idx
            .poll_id
            .prefix(self.metadata.id.u64())
            .range(self.store, None, None, Order::Ascending)
    }

    fn is(&self, state: PollState) -> bool {
        self.metadata.state == state
    }
}
