use std::collections::HashMap;

use cosmwasm_std::{Event, HexBinary, Uint64};
use serde_json::to_string;

pub struct SigningStarted {
    pub proof_id: String,
    pub sig_key_id: Uint64, // TODO: should this be here? type correct?
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
