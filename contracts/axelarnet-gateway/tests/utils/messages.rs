use router_api::{CrossChainId, Message};
use sha3::Digest;

use crate::utils::params;

pub fn dummy_from_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
        source_address: "source-address".parse().unwrap(),
        destination_chain: params::AXELARNET.parse().unwrap(),
        destination_address: "destination-address".parse().unwrap(),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}

pub fn dummy_to_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
        source_address: params::AXELARNET.parse().unwrap(),
        destination_chain: "destination-chain".parse().unwrap(),
        destination_address: "destination-address".parse().unwrap(),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}
