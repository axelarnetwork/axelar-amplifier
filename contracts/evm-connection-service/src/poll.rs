use cosmwasm_std::{Addr, Order, Storage, Uint256, Uint64};

use crate::{
    msg::ActionResponse,
    state::{tallied_votes, PollMetadata, PollState, ServiceInfo, TalliedVote, POLLS},
    utils::hash,
    ContractError,
};

pub enum VoteResult {
    NoVote,
    VoteInTime,
    VotedLate,
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

    pub fn has_voted(&self, voter: &Addr) -> bool {
        let result = self.get_tallied_votes().find(|item| {
            let (_, tallied_vote) = item.as_ref().unwrap();
            tallied_vote.is_voter_late.contains_key(voter)
        });

        match result {
            Some(_) => true,
            None => false,
        }
    }

    pub fn vote(
        &mut self,
        voter: Addr,
        block_height: u64,
        reply: ActionResponse,
    ) -> Result<VoteResult, ContractError> {
        if self.metadata.is(PollState::NonExistent) {
            return Err(ContractError::PollNonExistent {});
        }

        if self.has_voted(&voter) {
            return Err(ContractError::AlreadyVoted { voter });
        }

        if self
            .metadata
            .snapshot
            .get_participant_weight(&voter)
            .is_zero()
        {
            return Err(ContractError::NotEligibleToVote { voter });
        }

        if self.metadata.is(PollState::Failed) {
            return Ok(VoteResult::NoVote);
        }

        // TODO is in grace period / late voting

        if self.metadata.is(PollState::Completed) {
            return Ok(VoteResult::NoVote);
        }

        self.vote_before_completion(voter, block_height, reply)?;

        Ok(VoteResult::VoteInTime)
    }

    pub fn vote_before_completion(
        &mut self,
        voter: Addr,
        block_height: u64,
        reply: ActionResponse,
    ) -> Result<(), ContractError> {
        let hash = hash(&reply);

        let voting_power = self.metadata.snapshot.get_participant_weight(&voter);

        tallied_votes().update(
            self.store,
            (self.metadata.id.u64(), hash),
            |v| -> Result<TalliedVote, ContractError> {
                match v {
                    Some(mut tallied_vote) => {
                        tallied_vote.tally += voting_power;
                        tallied_vote.is_voter_late.insert(voter, false);
                        Ok(tallied_vote)
                    }
                    None => Ok(TalliedVote::new(voting_power, reply, self.metadata.id)),
                }
            },
        )?;

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

    pub fn has_enough_votes(&self, majority: &Uint256) -> bool {
        majority.ge(&self.passing_weight)
            && self.get_voter_count() >= self.service_info.min_voter_count
    }

    pub fn cannot_win(&self, majority: &Uint256) -> bool {
        let already_tallied = self.get_tallied_voting_power();
        let missing_voting_power =
            self.metadata.snapshot.get_participants_weight() - already_tallied;

        (*majority + missing_voting_power).lt(&self.passing_weight)
    }

    pub fn get_tallied_voting_power(&self) -> Uint256 {
        self.get_tallied_votes()
            .fold(Uint256::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum + tallied_vote.tally
            })
    }

    pub fn get_voter_count(&self) -> Uint64 {
        self.get_tallied_votes()
            .fold(Uint64::zero(), |accum, item| {
                let (_, tallied_vote) = item.as_ref().unwrap();
                accum + Uint64::from(tallied_vote.is_voter_late.len() as u64)
            })
    }

    pub fn get_majority_vote(&self) -> Result<TalliedVote, ContractError> {
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

    pub fn get_tallied_votes(
        &self,
    ) -> Box<(dyn Iterator<Item = Result<((u64, u64), TalliedVote), cosmwasm_std::StdError>> + '_)>
    {
        tallied_votes()
            .idx
            .poll_id
            .prefix(self.metadata.id.u64())
            .range(self.store, None, None, Order::Ascending)
    }
}
