use cosmwasm_std::{Storage, Uint64};
use cw_storage_plus::{Item, Map};

use crate::{
    signing::SigningSession,
    types::{Key, KeyID},
    ContractError,
};

pub const SIGNING_SESSION_COUNTER: Item<Uint64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");

// TODO: key management will change once keygen and key rotation are introduced
// Map key is currently owner address, however this will change to some derivation of it once keygen and keyrotation are introduced
pub const KEYS: Map<&KeyID, Key> = Map::new("keys");
pub fn get_key(store: &dyn Storage, key_id: &KeyID) -> Result<Key, ContractError> {
    KEYS.load(store, key_id)
        .map_err(|_| ContractError::NoActiveKeyFound {
            key_id: key_id.to_string(),
        })
}
