use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Decimal, Uint64};
use cw_storage_plus::{Item, Map};
use snapshotter::snapshot::Snapshot;

use crate::multisig::SigningSession;

#[cw_serde]
pub enum KeyState {
    Inactive,
    Assigned,
    Active,
}

// TODO: keyrotation logic
#[cw_serde]
pub struct Key {
    pub id: Uint64,
    pub snapshot: Snapshot,
    pub signing_treshhold: Decimal,
    pub state: KeyState, // TODO: not being used right now
    pub pub_keys: HashMap<Addr, Binary>,
}

impl Key {
    pub fn new(
        id: u64,
        snapshot: Snapshot,
        signing_treshhold: Decimal,
        pub_keys: HashMap<Addr, Binary>,
    ) -> Self {
        Self {
            id: Uint64::from(id),
            snapshot,
            signing_treshhold,
            state: KeyState::Active,
            pub_keys,
        }
    }
}

pub const KEYS_COUNTER: Item<u64> = Item::new("keys_counter");
pub const KEYS: Map<u64, Key> = Map::new("keys");
pub const SIGNING_SESSION_COUNTER: Item<u64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");
