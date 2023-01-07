use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256, Uint64};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use crate::{
    msg::{ActionMessage, ActionResponse},
    snapshot::Snapshot,
};

#[cw_serde]
pub struct ServiceInfo {
    pub service_registry: Addr,
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
pub struct Participant {
    pub address: Addr,
    pub weight: Uint256,
}

#[cw_serde]
pub struct PollMetadata {
    pub id: Uint64,
    pub expires_at: Uint64,
    pub result: Option<ActionResponse>,
    pub state: PollState,
    pub completed_at: Option<Uint64>,
    pub snapshot: Snapshot,
    pub message: ActionMessage,
}

impl PollMetadata {
    pub fn new(id: Uint64, expires_at: Uint64, snapshot: Snapshot, message: ActionMessage) -> Self {
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
}

#[cw_serde]
pub struct TalliedVote {
    pub tally: Uint256,
    pub data: ActionResponse,
    pub poll_id: Uint64,
    pub is_voter_late: HashMap<Addr, bool>,
}

impl TalliedVote {
    pub fn new(tally: Uint256, data: ActionResponse, poll_id: Uint64) -> Self {
        Self {
            tally,
            data,
            poll_id,
            is_voter_late: HashMap::new(),
        }
    }
}

pub struct TalliedVoteIndexes<'a> {
    pub poll_id: MultiIndex<'a, u64, TalliedVote, (u64, u64)>,
}

impl<'a> IndexList<TalliedVote> for TalliedVoteIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<TalliedVote>> + '_> {
        let v: Vec<&dyn Index<TalliedVote>> = vec![&self.poll_id];
        Box::new(v.into_iter())
    }
}

pub fn tallied_votes<'a>() -> IndexedMap<'a, (u64, u64), TalliedVote, TalliedVoteIndexes<'a>> {
    let indexes = TalliedVoteIndexes {
        poll_id: MultiIndex::new(
            |_pk, d| d.poll_id.u64(),
            "tallied_votes",
            "tallied_votes__poll_id",
        ),
    };
    IndexedMap::new("tallied_votes", indexes)
}

pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const POLL_COUNTER: Item<u64> = Item::new("poll_counter");
pub const POLLS: Map<u64, PollMetadata> = Map::new("polls");
