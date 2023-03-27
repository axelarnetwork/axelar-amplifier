use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, to_binary, Binary, Uint256};
use ethabi::{ethereum_types::U256, Token};
use sha3::{Digest, Keccak256};

use crate::{state::CommandBatch, ContractError};

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
    pub max_gas_cost: u32, // TODO: is necessary for cosmwasm?
}

#[cw_serde]
pub struct CommandBatchMetadata {
    pub chain_name: String, // TODO: probably not needed since this can be retrieved from gateway settings
    pub command_batch_id: [u8; 32],
}

pub fn new_validate_calls_hash_command(
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

fn pack_batch_arguments(
    chain_id: Uint256,
    commands_ids: &[[u8; 32]],
    commands: &[String],
    commands_params: Vec<Vec<u8>>,
) -> Vec<u8> {
    let chain_id_token = Token::Uint(U256::from_dec_str(&chain_id.to_string()).unwrap());
    let commands_ids_tokens: Vec<Token> = commands_ids
        .iter()
        .map(|item| Token::FixedBytes(item.to_vec()))
        .collect();
    let commands_tokens: Vec<Token> = commands
        .iter()
        .map(|item| Token::String(item.clone()))
        .collect();
    let commands_params_tokens: Vec<Token> = commands_params
        .iter()
        .map(|item| Token::Bytes(item.clone()))
        .collect();

    ethabi::encode(&[
        chain_id_token,
        Token::Array(commands_ids_tokens),
        Token::Array(commands_tokens),
        Token::Array(commands_params_tokens),
    ])
}

pub fn new_command_batch(
    block_height: u64,
    destination_chain_id: Uint256,
    destination_chain_name: &str,
    messages: Vec<Binary>,
) -> Result<CommandBatch, ContractError> {
    let mut commands_ids: Vec<[u8; 32]> = Vec::new();
    let mut commands: Vec<String> = Vec::new();
    let mut commands_params: Vec<Vec<u8>> = Vec::new();

    for message in messages {
        // TODO: filter per gas cost

        let command_type: CommandType = from_binary(&message)?;
        let command_type_string = command_type.to_string();

        let command = match command_type {
            CommandType::ValidateCallsHash {
                source_chain,
                calls_hash,
            } => new_validate_calls_hash_command(
                &source_chain,
                destination_chain_name,
                calls_hash,
                destination_chain_id,
                command_type_string,
            )?,
        };

        commands_ids.push(command.command_id);
        commands.push(command.command_type);
        commands_params.push(command.params);
    }

    let data = pack_batch_arguments(
        destination_chain_id,
        &commands_ids,
        &commands,
        commands_params,
    );

    Ok(CommandBatch::new(block_height, commands_ids, data))
}
