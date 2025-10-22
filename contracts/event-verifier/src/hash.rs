use axelar_wasm_std::hash::Hash;
use event_verifier_api::EventToVerify;
use router_api::FIELD_DELIMITER;
use sha3::{Digest, Keccak256};

pub fn hash_event_to_verify(event_to_verify: &EventToVerify) -> Hash {
    let mut hasher = Keccak256::new();
    let delimiter_bytes = &[FIELD_DELIMITER as u8];

    hasher.update(event_to_verify.source_chain.as_ref());
    hasher.update(delimiter_bytes);

    // event_data can contain the FIELD_DELIMITER, but this is ok as long as source_chain does not contain
    // the delimiter. Since event_data is the last field, it does not matter if the delimiter is contained within it.
    //
    // The field delimiter is meant to prevent two different inputs from producing the same hash
    // (i.e. by producing the same byte string when contatenated together).
    // For a given source chain, two different event_data values will always produce different hashes,
    // because the value hashed is always [source_chain] + [field delimiter] + [event_data]
    // For events with different source chains, the hash will always be different, because the chain names themselves
    // cannot be equal and thus the prefix of the data to be hashed is always different:
    // [source_chain_a] + [field delimiter] != [source_chain_b] + [field delimiter]
    // and [source_chain_a] + [field delimiter] is not a substring of [source_chain_b] + [field delimiter]
    // and [source_chain_b] + [field delimiter] is not a substring of [source_chain_a] + [field delimiter]
    hasher.update(event_to_verify.event_data.as_bytes());

    hasher.finalize().into()
}
