use axelar_core_std::nexus;
use cosmwasm_std::testing::MockApi;
use router_api::{chain_name_raw, CrossChainId, Message};
use sha3::Digest;

use crate::utils::params;

pub fn dummy_from_router(payload: &impl AsRef<[u8]>) -> Message {
    Message {
        cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
        source_address: "source-address".parse().unwrap(),
        destination_chain: params::AXELARNET.parse().unwrap(),
        destination_address: MockApi::default()
            .addr_make("destination-address")
            .to_string()
            .parse()
            .unwrap(),
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

pub fn dummy_from_nexus(payload: &impl AsRef<[u8]>) -> nexus::execute::Message {
    nexus::execute::Message {
        source_chain: chain_name_raw!("Ethereum"),
        source_address: "source-address".parse().unwrap(),
        destination_chain: "destination-chain".parse().unwrap(),
        destination_address: "destination-address".parse().unwrap(),
        payload_hash: sha3::Keccak256::digest(payload).into(),
        source_tx_id: "source-chain".as_bytes().to_vec().try_into().unwrap(),
        source_tx_index: 0,
        id: "source-chain-0".to_string(),
    }
}
