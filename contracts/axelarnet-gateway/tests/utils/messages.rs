use axelar_core_std::nexus;
use router_api::{address, chain_name, chain_name_raw, cosmos_address, CrossChainId, Message};
use sha3::Digest;

use crate::utils::params;

pub fn dummy_from_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new(params::SOURCE_CHAIN, "hash-index").unwrap(),
        source_address: address!(params::SOURCE_ADDRESS),
        destination_chain: chain_name!(params::AXELARNET),
        destination_address: cosmos_address!(params::DESTINATION_ADDRESS),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}

pub fn dummy_to_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new(params::SOURCE_CHAIN, "hash-index").unwrap(),
        source_address: address!(params::AXELARNET),
        destination_chain: chain_name!(params::DESTINATION_CHAIN),
        destination_address: address!(params::DESTINATION_ADDRESS),
        payload_hash: sha3::Keccak256::digest(payload).into(),
    }
}

pub fn dummy_from_nexus(payload: &impl AsRef<[u8]>) -> nexus::execute::Message {
    nexus::execute::Message {
        source_chain: chain_name_raw!("Ethereum"),
        source_address: address!(params::SOURCE_ADDRESS),
        destination_chain: chain_name!(params::DESTINATION_CHAIN),
        destination_address: address!(params::DESTINATION_ADDRESS),
        payload_hash: sha3::Keccak256::digest(payload).into(),
        source_tx_id: params::SOURCE_CHAIN.as_bytes().to_vec().try_into().unwrap(),
        source_tx_index: 0,
        id: "source-chain-0".to_string(),
    }
}
