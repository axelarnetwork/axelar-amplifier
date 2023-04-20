use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Uint256, Uint64};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};
use snapshotter::snapshot::Snapshot;

use crate::utils::hash;

#[cw_serde]
pub enum PollState {
    Pending,
    Completed,
    Failed,
}

impl Display for PollState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollState::Pending => write!(f, "Pending"),
            PollState::Completed => write!(f, "Completed"),
            PollState::Failed => write!(f, "Failed"),
        }
    }
}

#[cw_serde]
pub struct Poll {
    pub id: Uint64,
    pub expires_at: Uint64, // TODO: this is used for end blocker, how is end blocker logic being handled in cosmwasm? Split endblockr logc and decide later who will trigger logic
    pub result: Option<Binary>,
    pub state: PollState,
    pub completed_at: Option<Uint64>,
    pub snapshot: Snapshot,
    pub message: Binary,
}

#[cw_serde]
pub struct TalliedVote {
    pub tally: Uint256,
    pub data: Binary,
    pub poll_id: Uint64,
    pub is_voter_late_namespace: String,
}

impl TalliedVote {
    pub fn new(tally: Uint256, data: Binary, poll_id: Uint64) -> Self {
        let hash = hash(&data);
        let namespace = format!("is_voter_late_{}{}", poll_id.u64(), hash);
        Self {
            tally,
            data,
            poll_id,
            is_voter_late_namespace: namespace,
        }
    }

    pub fn is_voter_late_map(&self) -> Map<&Addr, bool> {
        Map::new(&self.is_voter_late_namespace)
    }
}

pub fn is_voter_late_map(namespace: &str) -> Map<&Addr, bool> {
    // TODO: convert to HashMap?
    Map::new(namespace)
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

pub const POLL_COUNTER: Item<u64> = Item::new("poll_counter");
pub const POLLS: Map<u64, Poll> = Map::new("polls");
