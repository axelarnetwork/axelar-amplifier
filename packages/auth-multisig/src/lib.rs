mod error;
pub mod multisig;
mod state;
use std::{collections::HashMap, ops::ControlFlow};

pub use crate::error::AuthError;

use auth::AuthModule;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Binary, BlockInfo, Decimal, DepsMut, Order, StdResult, Storage, Uint256, Uint64,
};
use multisig::{get_current_key_id, MultisigState, SigningSession, WorkerSignature};
use service_registry::{msg::ActiveWorkers, state::Worker};
use snapshotter::snapshot::Snapshot;
use state::{Key, KeyState, KEYS, KEYS_COUNTER, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER};

#[cw_serde]
pub struct AuthMultisig {
    pub signing_timeout: Uint64,
    pub signing_grace_period: Uint64,
}

pub struct InitAuthModuleParameters<'a> {
    pub store: &'a mut dyn Storage,
}

pub struct InitializeAuthSessionParameters<'a> {
    pub store: &'a mut dyn Storage,
    pub block_height: u64,
    pub payload_hash: [u8; 32],
    pub metadata: Binary,
}

pub struct SubmitWorkerValidationParameters<'a> {
    pub store: &'a mut dyn Storage,
    pub signing_session_id: Uint64,
    pub signer: Addr,
    pub block_height: u64,
    pub signature: Binary,
}

pub struct FinalizePendingSessionsParameters<'a> {
    pub store: &'a mut dyn Storage,
    pub limit: u32,
    pub block_height: u64,
    pub pending_signing_handler: &'a mut dyn FnMut(&SigningSession),
    pub completed_signing_handler: &'a mut dyn FnMut(&SigningSession),
}

impl<'a> AuthModule<'a> for AuthMultisig {
    type InitAuthModuleParameters = InitAuthModuleParameters<'a>;
    type InitAuthModuleResult = StdResult<()>;
    type InitializeAuthSessionParameters = InitializeAuthSessionParameters<'a>;
    type InitializeAuthSessionResult = Result<SigningSession, AuthError>;
    type SubmitWorkerValidationParameters = SubmitWorkerValidationParameters<'a>;
    type SubmitWorkerValidationResult = Result<(), AuthError>;
    type FinalizePendingSessionsParameters = FinalizePendingSessionsParameters<'a>;
    type FinalizePendingSessionsResult = Result<Vec<SigningSession>, AuthError>;

    fn init_auth_module(
        &self,
        parameters: Self::InitAuthModuleParameters,
    ) -> Self::InitAuthModuleResult {
        SIGNING_SESSION_COUNTER.save(parameters.store, &0)?;
        KEYS_COUNTER.save(parameters.store, &0)
    }

    fn initialize_auth_session(
        &self,
        parameters: Self::InitializeAuthSessionParameters,
    ) -> Self::InitializeAuthSessionResult {
        let key_id = get_current_key_id(parameters.store)?;

        let key = KEYS
            .load(parameters.store, key_id.u64())
            .map_err(|_| AuthError::KeyNotFound { key: key_id })?;

        if key.state != KeyState::Active {
            return Err(AuthError::KeyNotActive { key: key_id });
        }

        let expires_at = self.signing_timeout + Uint64::from(parameters.block_height);
        let sig_session_id = SIGNING_SESSION_COUNTER.update(
            parameters.store,
            |mut counter| -> Result<u64, AuthError> {
                counter += 1;
                Ok(counter)
            },
        )?;
        let signing_session = SigningSession::new(
            Uint64::from(sig_session_id),
            &key,
            parameters.payload_hash,
            expires_at,
            self.signing_grace_period,
            parameters.metadata,
        );
        SIGNING_SESSIONS.save(parameters.store, sig_session_id, &signing_session)?;

        Ok(signing_session)
    }

    fn submit_worker_validation(
        &self,
        parameters: Self::SubmitWorkerValidationParameters,
    ) -> Self::SubmitWorkerValidationResult {
        let mut signing_session =
            SIGNING_SESSIONS.load(parameters.store, parameters.signing_session_id.u64())?;

        signing_session.add_signature(
            parameters.block_height,
            parameters.signer,
            WorkerSignature(parameters.signature),
        )?;

        SIGNING_SESSIONS.save(parameters.store, signing_session.id.u64(), &signing_session)?;

        Ok(())
    }

    fn finalize_open_sessions(
        &self,
        parameters: Self::FinalizePendingSessionsParameters,
    ) -> Self::FinalizePendingSessionsResult {
        let mut expired_signing_sessions: Vec<SigningSession> = Vec::new();

        // TODO: consider using pagination instead of removing? https://github.com/CosmWasm/cw-storage-plus#prefix.
        // Can't remove polls in the same iteration because borrow checker complains.
        SIGNING_SESSIONS
            .range(parameters.store, None, None, Order::Ascending)
            .try_for_each(|item| {
                let (_, sig_session) = item.unwrap();

                if expired_signing_sessions.len() >= parameters.limit.try_into().unwrap() {
                    return ControlFlow::Break(());
                }

                if sig_session.expires_at.u64() <= parameters.block_height {
                    expired_signing_sessions.push(sig_session);
                }

                ControlFlow::Continue(())
            });

        for sig_session in &expired_signing_sessions {
            match sig_session.state {
                MultisigState::Pending => (parameters.pending_signing_handler)(sig_session),
                MultisigState::Completed => (parameters.completed_signing_handler)(sig_session),
            }

            SIGNING_SESSIONS.remove(parameters.store, sig_session.id.u64());
        }

        Ok(expired_signing_sessions)
    }
}

impl AuthMultisig {
    pub fn set_pub_keys(
        &self,
        deps: DepsMut,
        block: BlockInfo,
        active_workers: ActiveWorkers,
        signing_treshold: Decimal,
        pub_keys: HashMap<Addr, Binary>,
    ) -> Result<(), AuthError> {
        let id = KEYS_COUNTER.update(deps.storage, |mut counter| -> Result<u64, AuthError> {
            counter += 1;
            Ok(counter)
        })?;

        let filter_fn =
            &|_deps: &DepsMut, worker: &Worker| -> bool { pub_keys.contains_key(&worker.address) };
        let weight_fn =
            &|_deps: &DepsMut, _worker: &Worker| -> Option<Uint256> { Some(Uint256::one()) };

        let snapshot = Snapshot::new(
            &deps,
            block.time,
            Uint64::from(block.height),
            active_workers,
            filter_fn,
            weight_fn,
        );

        let key = Key::new(id, snapshot, signing_treshold, pub_keys);

        KEYS.save(deps.storage, id, &key)?;

        Ok(())
    }
}
