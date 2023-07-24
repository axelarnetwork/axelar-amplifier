use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_std::{HexBinary, Uint256};
use multisig::types::{PublicKey, Signature};

use super::{Data, Message};

pub trait CommandBatch {
    fn new(block_height: u64, messages: Vec<Message>, destination_chain_id: Uint256) -> Self;
}

pub trait Proof {
    fn new(
        snapshot: Snapshot,
        signatures: HashMap<String, Signature>,
        pub_keys: HashMap<String, PublicKey>,
    ) -> Self;

    fn encode_execute_data(&self, data: &Data) -> HexBinary;
}
