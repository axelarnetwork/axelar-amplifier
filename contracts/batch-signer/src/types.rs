use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};
use std::fmt::Display;

pub type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std, probably change to newtype with hex encoding (HexBinary/[u8;32])

// TODO: this doesn't belong in this contract
// TODO: should this be an enum of different types of commands?
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: String,
    pub payload_hash: HexBinary,
}

// TODO: confirm message id format
impl Message {
    pub fn source_tx_hash(&self) -> HexBinary {
        let parts: Vec<&str> = self.id.split('-').collect();

        HexBinary::from_hex(parts[0])
            .expect("violated invariant: message id cannot be parsed to tx hash")
    }

    pub fn source_event_index(&self) -> Uint64 {
        let parts: Vec<&str> = self.id.split('-').collect();

        Uint64::try_from(parts[1])
            .expect("violated invariant: message id cannot be parsed to event index")
    }
}

// TODO: this would most likely change when other command types are supported
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
