mod error;
mod poll;
mod state;
mod utils;
pub use crate::error::AuthError;

use crate::poll::VoteResult;
use crate::state::{Poll, POLLS, POLL_COUNTER};
use auth::AuthModule;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Binary, BlockInfo, Decimal, DepsMut, StdResult, Storage, Uint256, Uint64,
};
use service_registry::msg::ActiveWorkers;
use service_registry::state::Worker;
use snapshotter::snapshot::Snapshot;

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

pub struct FinalizePendingSessionsParameters {}

impl<'a> AuthModule<'a> for AuthVoting {
    type InitAuthModuleParameters = InitAuthModuleParameters<'a>;
    type InitAuthModuleResult = StdResult<()>;
    type InitializeAuthSessionParameters = InitializeAuthSessionParameters<'a>;
    type InitializeAuthSessionResult = Result<Poll, AuthError>;
    type SubmitWorkerValidationParameters = SubmitWorkerValidationParameters<'a>;
    type SubmitWorkerValidationResult = Result<(Poll, VoteResult), AuthError>;
    type FinalizePendingSessionsParameters = FinalizePendingSessionsParameters;
    type FinalizePendingSessionsResult = Result<(), AuthError>;

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

    fn finalize_pending_sessions(
        &self,
        _parameters: Self::FinalizePendingSessionsParameters,
    ) -> Self::FinalizePendingSessionsResult {
        // TODO: React to poll state
        todo!()
    }
}
