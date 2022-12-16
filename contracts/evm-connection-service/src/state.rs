use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint64};
use cw_storage_plus::{Item, Map};

use crate::msg::{ActionMessage, ActionResponse};

#[cw_serde]
pub struct ServiceInfo {
    pub name: String,
    pub voting_threshold: Uint64,
    pub min_voter_count: Uint64,
    pub reward_pool: Addr,
    pub voting_period: Uint64,
    pub voting_grace_period: Uint64,
}

#[cw_serde]
pub enum PollState {
    NonExistent,
    Pending,
    Completed,
    Failed,
}

#[cw_serde]
pub struct PollMetadata {
    pub id: Uint64,
    pub expires_at: Uint64,
    pub result: Option<ActionResponse>,
    pub state: PollState,
    pub completed_at: Option<Uint64>,
    // TODO: snapshot
    pub message: ActionMessage,
}

impl PollMetadata {
    pub fn new(id: Uint64, expires_at: Uint64, message: ActionMessage) -> Self {
        Self {
            id,
            expires_at,
            result: None,
            state: PollState::Pending,
            completed_at: None,
            message,
        }
    }
}

pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const POLL_COUNTER: Item<u64> = Item::new("poll_counter");
pub const POLLS: Map<u64, PollMetadata> = Map::new("polls");
