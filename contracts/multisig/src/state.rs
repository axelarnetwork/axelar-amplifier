use std::collections::HashMap;

use cosmwasm_std::{Addr, HexBinary, Order, StdResult, Storage, Uint64};
use cw_storage_plus::{Item, Map};

use crate::{
    key::{KeyType, Signature},
    signing::SigningSession,
    types::{Key, KeyID},
    ContractError,
};

pub const SIGNING_SESSION_COUNTER: Item<Uint64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");

/// Signatures by session id and signer address
pub const SIGNATURES: Map<(u64, &str), Signature> = Map::new("signatures");

pub fn load_session_signatures(
    store: &dyn Storage,
    session_id: u64,
) -> StdResult<HashMap<String, Signature>> {
    SIGNATURES
        .prefix(session_id)
        .range(store, None, None, Order::Ascending)
        .collect()
}

pub fn save_signature(
    store: &mut dyn Storage,
    session_id: Uint64,
    signature: Signature,
    signer: &Addr,
) -> Result<Signature, ContractError> {
    SIGNATURES.update(
        store,
        (session_id.u64(), signer.as_ref()),
        |sig| -> Result<Signature, ContractError> {
            match sig {
                Some(_) => Err(ContractError::DuplicateSignature {
                    session_id,
                    signer: signer.into(),
                }),
                None => Ok(signature),
            }
        },
    )
}

pub const KEYS: Map<&KeyID, Key> = Map::new("keys");
pub fn get_key(store: &dyn Storage, key_id: &KeyID) -> Result<Key, ContractError> {
    KEYS.load(store, key_id)
        .map_err(|_| ContractError::NoActiveKeyFound {
            key_id: key_id.to_string(),
        })
}

// key type is part of the key so signers can register multiple keys with different types
pub const PUB_KEYS: Map<(Addr, KeyType), HexBinary> = Map::new("registered_pub_keys");
