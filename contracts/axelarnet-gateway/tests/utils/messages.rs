use cosmwasm_std::{from_json, CosmosMsg, Response, WasmMsg};
use router_api::{CrossChainId, Message};
use serde::de::DeserializeOwned;
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

pub fn inspect_response_msg<T>(response: Response) -> Result<T, ()>
where
    T: DeserializeOwned,
{
    let mut followup_messages = response.messages.into_iter();

    let msg = followup_messages.next().ok_or(())?.msg;

    if followup_messages.next().is_some() {
        return Err(());
    }

    match msg {
        CosmosMsg::Wasm(WasmMsg::Execute { msg, .. }) => from_json(msg).map_err(|_| ()),
        _ => Err(()),
    }
}
