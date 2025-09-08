use axelar_wasm_std::hash::Hash;
use router_api::FIELD_DELIMITER;
use sha3::{Digest, Keccak256};

use crate::msg::EventToVerify;
use event_verifier_api::{Event, TransactionDetails};

pub fn hash_transaction_details(transaction_details: &TransactionDetails) -> Hash {
    let mut hasher = Keccak256::new();
    let delimiter_bytes = &[FIELD_DELIMITER as u8];

    hasher.update(transaction_details.calldata.as_slice());
    hasher.update(delimiter_bytes);
    hasher.update(transaction_details.from.as_str());
    hasher.update(delimiter_bytes);
    hasher.update(transaction_details.to.as_str());
    hasher.update(delimiter_bytes);
    hasher.update(transaction_details.value.to_string().as_bytes());
    hasher.update(delimiter_bytes);

    hasher.finalize().into()
}

pub fn hash_event(event: &Event) -> Hash {
    let mut hasher = Keccak256::new();
    let delimiter_bytes = &[FIELD_DELIMITER as u8];

    hasher.update(event.contract_address.as_str());
    hasher.update(delimiter_bytes);
    hasher.update(&event.event_index.to_le_bytes());
    hasher.update(delimiter_bytes);
    
    // Hash each topic
    for topic in &event.topics {
        hasher.update(topic.as_slice());
        hasher.update(delimiter_bytes);
    }
    
    hasher.update(event.data.as_slice());
    hasher.update(delimiter_bytes);

    hasher.finalize().into()
}

pub fn hash_event_to_verify(event_to_verify: &EventToVerify) -> Hash {
    let mut hasher = Keccak256::new();
    let delimiter_bytes = &[FIELD_DELIMITER as u8];

    hasher.update(event_to_verify.source_chain.as_ref());
    hasher.update(delimiter_bytes);
    
    // Parse the event data to get the transaction hash
    // Note: This assumes the event_data is a JSON string that can be deserialized
    // The actual implementation may need to be adjusted based on how the data is structured
    hasher.update(event_to_verify.event_data.as_bytes());

    hasher.finalize().into()
}
