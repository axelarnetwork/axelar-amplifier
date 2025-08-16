use axelar_core_std::nexus;
use router_api::{address, chain_name_raw, cosmos_address, CrossChainId, Message};
use sha3::Digest;

pub fn dummy_from_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
        source_address: router_api::SOURCE_ADDRESS.clone(),
        destination_chain: router_api::AXELARNET_CHAIN_NAME.clone(),
        destination_address: cosmos_address!("destination-address"),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}

pub fn dummy_to_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
        source_address: address!("axelarnet"),
        destination_chain: router_api::DESTINATION_CHAIN_NAME.clone(),
        destination_address: router_api::DESTINATION_ADDRESS.clone(),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}

pub fn dummy_from_nexus(payload: &impl AsRef<[u8]>) -> nexus::execute::Message {
    nexus::execute::Message {
        source_chain: chain_name_raw!("Ethereum"),
        source_address: router_api::SOURCE_ADDRESS.clone(),
        destination_chain: router_api::DESTINATION_CHAIN_NAME.clone(),
        destination_address: router_api::DESTINATION_ADDRESS.clone(),
        payload_hash: sha3::Keccak256::digest(payload).into(),
        source_tx_id: "source-chain".as_bytes().to_vec().try_into().unwrap(),
        source_tx_index: 0,
        id: "source-chain-0".to_string(),
    }
}
