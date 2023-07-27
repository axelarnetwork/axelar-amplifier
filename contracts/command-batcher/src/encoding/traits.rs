use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use connection_router::msg::Message;
use cosmwasm_std::{HexBinary, Uint256};
use multisig::types::Signature;

use crate::{
    error::ContractError,
    types::{CommandBatch, Data, Proof},
};

pub trait Builder {
    fn build_batch(
        block_height: u64,
        messages: Vec<Message>,
        destination_chain_id: Uint256,
    ) -> Result<CommandBatch, ContractError>;

    fn build_proof(
        snapshot: Snapshot,
        signers: HashMap<String, Signature>,
        pub_keys: HashMap<String, multisig::types::PublicKey>,
    ) -> Result<Proof, ContractError>;
}

pub trait Encoder {
    fn encode_execute_data(data: &Data, proof: &Proof) -> HexBinary;
}
