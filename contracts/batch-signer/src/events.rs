use std::collections::HashMap;

use cosmwasm_std::{Addr, Event, HexBinary, Uint64};
use serde_json::to_string;

use crate::types::KeccackHash;

pub struct SigningStarted {
    pub proof_id: String,
    pub sig_key_id: Uint64,
    pub pub_keys: HashMap<String, HexBinary>,
    pub unsigned_hash: HexBinary,
}

impl From<SigningStarted> for Event {
    fn from(other: SigningStarted) -> Self {
        Event::new("signing_started")
            .add_attribute("proof_id", other.proof_id)
            .add_attribute("sig_key_id", other.sig_key_id)
            .add_attribute(
                "pub_keys",
                to_string(&other.pub_keys)
                    .expect("violated invariant: pub_keys are not serializable"),
            )
            .add_attribute("unsigned_hash", other.unsigned_hash.to_hex())
    }
}

pub struct Sign {
    pub chain: String,
    pub sender: Addr,
    pub proof_id: String,
    pub commands_ids: Vec<KeccackHash>,
}

impl From<Sign> for Event {
    fn from(other: Sign) -> Self {
        Event::new("sign")
            .add_attribute("chain", other.chain)
            .add_attribute("sender", other.sender)
            .add_attribute("proof_id", other.proof_id)
            .add_attribute(
                "commands_ids",
                format!(
                    "[{}]",
                    other
                        .commands_ids
                        .iter()
                        .map(hex::encode) // TODO: move conversion to type impl?
                        .collect::<Vec<String>>()
                        .join(",")
                ),
            )
    }
}
