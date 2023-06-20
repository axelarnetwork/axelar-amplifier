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
    pub key_set_id: Uint64,
    pub sig_msg: HexBinary,
    pub signatures: HashMap<String, HexBinary>,
    pub state: MultisigState,
}

impl SigningSession {
    pub fn new(sig_session_id: Uint64, key_set_id: Uint64, sig_msg: HexBinary) -> Self {
        Self {
            id: sig_session_id,
            key_set_id,
            sig_msg,
            signatures: HashMap::new(),
            state: MultisigState::Pending,
        }
    }
}
