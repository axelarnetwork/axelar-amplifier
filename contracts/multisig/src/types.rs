use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint64};

#[cw_serde]
pub struct KeySet {
    pub id: Uint64,
    pub snapshot: Snapshot,
    pub pub_keys: HashMap<String, HexBinary>,
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}
#[cw_serde]
pub struct SigningSession {
    pub id: Uint64,
    pub key_id: Uint64,
    pub msg: HexBinary,
    pub signatures: HashMap<String, HexBinary>,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(sig_id: Uint64, key_id: Uint64, msg: HexBinary) -> Self {
        Self {
            id: sig_id,
            key_id,
            msg,
            signatures: HashMap::new(),
            state: MultisigState::Pending,
        }
    }
}
