mod error;
mod poll;
pub mod state;
mod utils;
use std::ops::ControlFlow;

pub use crate::error::AuthError;
pub use crate::state::Poll;

use crate::poll::VoteResult;
use crate::state::{POLLS, POLL_COUNTER};
use auth::AuthModule;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Binary, BlockInfo, Decimal, DepsMut, Order, StdResult, Storage, Uint256, Uint64,
};
use service_registry::msg::ActiveWorkers;
use service_registry::state::Worker;
use snapshotter::snapshot::Snapshot;
use state::PollState;

#[cw_serde]
pub struct AuthVoting {
    pub voting_threshold: Decimal,
    pub min_voter_count: Uint64,
    pub voting_period: Uint64,
    pub voting_grace_period: Uint64,
}

pub struct InitAuthModuleParameters<'a> {
    pub store: &'a mut dyn Storage,
}

pub struct InitializeAuthSessionParameters<'a> {
    pub deps: DepsMut<'a>,
    pub block: BlockInfo,
    pub active_workers: ActiveWorkers,
    pub message: Binary,
    pub filter_fn: &'a dyn Fn(&DepsMut, &Worker) -> bool,
    pub weight_fn: &'a dyn Fn(&DepsMut, &Worker) -> Option<Uint256>,
}

pub struct SubmitWorkerValidationParameters<'a> {
    pub store: &'a mut dyn Storage,
    pub poll_id: Uint64,
    pub voter: Addr,
    pub block_height: u64,
    pub vote: Binary,
}

pub struct FinalizePendingSessionsParameters<'a> {
    pub store: &'a mut dyn Storage,
    pub limit: u32,
    pub block_height: u64,
    pub pending_poll_handler: &'a mut dyn FnMut(&Poll),
    pub failed_poll_handler: &'a mut dyn FnMut(&Poll),
    pub completed_poll_handler: &'a mut dyn FnMut(&Poll),
}

impl<'a> AuthModule<'a> for AuthVoting {
    type InitAuthModuleParameters = InitAuthModuleParameters<'a>;
    type InitAuthModuleResult = StdResult<()>;
    type InitializeAuthSessionParameters = InitializeAuthSessionParameters<'a>;
    type InitializeAuthSessionResult = Result<Poll, AuthError>;
    type SubmitWorkerValidationParameters = SubmitWorkerValidationParameters<'a>;
    type SubmitWorkerValidationResult = Result<(Poll, VoteResult), AuthError>;
    type FinalizePendingSessionsParameters = FinalizePendingSessionsParameters<'a>;
    type FinalizePendingSessionsResult = Result<Vec<Poll>, AuthError>;

    fn init_auth_module(
        &self,
        parameters: Self::InitAuthModuleParameters,
    ) -> Self::InitAuthModuleResult {
        POLL_COUNTER.save(parameters.store, &0)
    }

    fn initialize_auth_session(
        &self,
        parameters: Self::InitializeAuthSessionParameters,
    ) -> Self::InitializeAuthSessionResult {
        let id = POLL_COUNTER.update(
            parameters.deps.storage,
            |mut counter| -> Result<u64, AuthError> {
                counter += 1;
                Ok(counter)
            },
        )?;

        let expires_at = parameters.block.height + self.voting_period.u64();

        let snapshot = Snapshot::new(
            &parameters.deps,
            parameters.block.time,
            Uint64::from(parameters.block.height),
            parameters.active_workers,
            parameters.filter_fn,
            parameters.weight_fn,
        );

        let poll_metadata = Poll::new(
            Uint64::from(id),
            Uint64::from(expires_at),
            snapshot,
            parameters.message,
        );

        POLLS.save(parameters.deps.storage, id, &poll_metadata)?;

        Ok(poll_metadata)
    }

    fn submit_worker_validation(
        &self,
        parameters: Self::SubmitWorkerValidationParameters,
    ) -> Self::SubmitWorkerValidationResult {
        let metadata = POLLS.may_load(parameters.store, parameters.poll_id.u64())?;

        if metadata.is_none() {
            return Err(AuthError::PollNonExistent {
                poll_id: parameters.poll_id,
            });
        }

        let mut poll = metadata.unwrap();

        let vote_result = poll.vote(
            parameters.store,
            self,
            &parameters.voter,
            parameters.block_height,
            parameters.vote,
        )?;

        Ok((poll, vote_result))
    }

    fn finalize_open_sessions(
        &self,
        parameters: Self::FinalizePendingSessionsParameters,
    ) -> Self::FinalizePendingSessionsResult {
        let mut expired_polls: Vec<Poll> = Vec::new();

        // TODO: consider using pagination instead of removing? https://github.com/CosmWasm/cw-storage-plus#prefix.
        // Can't remove polls in the same iteration because borrow checker complains.
        POLLS
            .range(parameters.store, None, None, Order::Ascending)
            .try_for_each(|item| {
                let (_, poll) = item.unwrap();

                if expired_polls.len() >= parameters.limit.try_into().unwrap() {
                    return ControlFlow::Break(());
                }

                if poll.expires_at.u64() <= parameters.block_height {
                    expired_polls.push(poll);
                }

                ControlFlow::Continue(())
            });

        for poll in &expired_polls {
            match poll.state {
                PollState::Pending => (parameters.pending_poll_handler)(poll),
                PollState::Failed => (parameters.failed_poll_handler)(poll),
                PollState::Completed => (parameters.completed_poll_handler)(poll),
            }

            POLLS.remove(parameters.store, poll.id.u64());
        }

        Ok(expired_polls)
    }
}
