use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256};
use std::fmt::Display;

pub type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std, probably change to newtype with hex encoding (HexBinary/[u8;32])

// TODO this doesn't belong in this contract
// TODO: should this be an enum of different types of commands?
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: String,
    pub payload_hash: HexBinary,
    pub source_tx_hash: HexBinary,
    pub source_event_index: Uint256,
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "approveContractCall")
    }
}

#[cw_serde]
pub struct Proof {
    pub addresses: Vec<Addr>,
    pub weights: Vec<Uint256>,
    pub threshold: Uint256,
    pub signatures: Vec<HexBinary>,
}
