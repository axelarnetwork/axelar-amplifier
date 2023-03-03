use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, Storage, Uint256, Uint64};
use ethabi::Token;
use sha3::{Digest, Keccak256};

use crate::{multisig::get_current_key_id, ContractError};

const VALIDATE_CALLS_HASH_MAX_GAS_COST: u32 = 100000;

#[cw_serde]
pub enum CommandType {
    ValidateCallsHash {
        source_chain: String,
        calls_hash: [u8; 32],
    },
}

impl Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::ValidateCallsHash {
                source_chain: _,
                calls_hash: _,
            } => write!(f, "validateCallsHash"),
        }
    }
}

#[cw_serde]
pub struct Command {
    pub command_id: [u8; 32],
    pub command_type: String,
    pub params: Vec<u8>,
    pub key_id: Uint64,
    pub max_gas_cost: u32, // TODO: is necessary for cosmwasm?
}

pub fn new_validate_calls_hash_command(
    store: &mut dyn Storage,
    source_chain: &str,
    destination_chain: &str,
    calls_hash: [u8; 32],
    destination_chain_id: Uint256,
    command_type: String,
) -> Result<Command, ContractError> {
    let chain_id_bytes = to_binary(&destination_chain_id).unwrap().to_vec();

    let mut hasher = Keccak256::new();
    hasher.update(source_chain);
    hasher.update(destination_chain);
    hasher.update(calls_hash);
    hasher.update(chain_id_bytes);
    let command_id: [u8; 32] = hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length");

    let command = Command {
        command_id,
        command_type,
        params: create_validate_calls_hash_params(source_chain, destination_chain, calls_hash),
        key_id: get_current_key_id(store)?,
        max_gas_cost: VALIDATE_CALLS_HASH_MAX_GAS_COST, // TODO: needs to be used
    };

    Ok(command)
}

fn create_validate_calls_hash_params(
    source_chain: &str,
    destination_chain: &str,
    calls_hash: [u8; 32],
) -> Vec<u8> {
    let source_chain_token = Token::String(source_chain.to_string());
    let destination_chain_token = Token::String(destination_chain.to_string());
    let calls_hash_token = Token::FixedBytes(calls_hash.to_vec());

    ethabi::encode(&[
        source_chain_token,
        destination_chain_token,
        calls_hash_token,
    ])
}
