use axelar_wasm_std::hash::Hash;
use router_api::FIELD_DELIMITER;
use sha3::{Digest, Keccak256};

use event_verifier_api::EventToVerify;

pub fn hash_event_to_verify(event_to_verify: &EventToVerify) -> Hash {
    let mut hasher = Keccak256::new();
    let delimiter_bytes = &[FIELD_DELIMITER as u8];

    hasher.update(event_to_verify.source_chain.as_ref());
    hasher.update(delimiter_bytes);

    hasher.update(event_to_verify.event_data.as_bytes());

    hasher.finalize().into()
}
