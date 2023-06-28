use cosmwasm_std::{Addr, Storage, Uint64};
use cw_storage_plus::{Item, Map};

use crate::{
    types::{Key, SigningSession},
    ContractError,
};

pub const SIGNING_SESSION_COUNTER: Item<Uint64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");

// TODO: revisit key storage once keygen and key rotation are defined
pub const KEY_SETS: Map<u64, Key> = Map::new("key_sets");
pub const CURRENT_KEY_ID: Map<&Addr, Uint64> = Map::new("current_key_id");

pub fn get_current_key_set(store: &dyn Storage, owner: &Addr) -> Result<Key, ContractError> {
    // TODO: revisit implementation once keygen and key rotation are defined
    let key_id =
        CURRENT_KEY_ID
            .load(store, owner)
            .map_err(|_| ContractError::NoActiveKeyFound {
                owner: owner.into(),
            })?;

    KEY_SETS
        .load(store, key_id.u64())
        .map_err(|_| ContractError::NoActiveKeyFound {
            owner: owner.into(),
        })
}
