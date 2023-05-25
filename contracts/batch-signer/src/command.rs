use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types::U256, Token};
use sha3::{Digest, Keccak256};

use crate::types::{KeccackHash, Message};

#[cw_serde]
pub enum SigningStatus {
    Signing,
    Aborted,
    Signed,
}

#[cw_serde]
pub struct CommandBatch {
    pub id: KeccackHash,
    pub commands_ids: Vec<KeccackHash>,
    pub encoded_data: HexBinary,
    pub unsigned_hash: KeccackHash,
    pub status: SigningStatus,
}

impl CommandBatch {
    pub fn new(block_height: u64, messages: Vec<Message>, destination_chain_id: Uint256) -> Self {
        let (commands_ids, commands_types, commands_params) = build_commands_data(messages);

        let encoded_data = encode_data(
            &destination_chain_id,
            &commands_ids,
            &commands_types,
            commands_params,
        );
        let id = build_batch_id(block_height, &encoded_data);
        let unsigned_hash = build_unsigned_hash(&encoded_data);

        Self {
            id,
            commands_ids,
            encoded_data,
            unsigned_hash,
            status: SigningStatus::Signing,
        }
    }
}

fn build_batch_id(block_height: u64, data: &HexBinary) -> KeccackHash {
    let mut id_hasher = Keccak256::new();
    id_hasher.update(block_height.to_be_bytes());
    id_hasher.update(data.as_slice());
    id_hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length")
}

fn build_commands_data(messages: Vec<Message>) -> (Vec<KeccackHash>, Vec<String>, Vec<HexBinary>) {
    let mut commands_ids: Vec<KeccackHash> = Vec::new();
    let mut commands_types: Vec<String> = Vec::new();
    let mut commands_params: Vec<HexBinary> = Vec::new();

    for message in messages {
        let command_type = message.to_string();
        let command_id = Keccak256::digest(message.id)
            .as_slice()
            .try_into()
            .expect("Wrong length");

        commands_ids.push(command_id);
        commands_types.push(command_type);
        commands_params.push(encode_command_params(
            message.source_chain,
            message.source_address,
            message.destination_address,
            message.payload_hash,
            message.source_tx_hash,
            message.source_event_index,
        ));
    }

    (commands_ids, commands_types, commands_params)
}

fn encode_command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
    source_tx_hash: HexBinary,
    source_event_index: Uint256,
) -> HexBinary {
    ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::String(destination_address),
        Token::FixedBytes(payload_hash.into()),
        Token::FixedBytes(source_tx_hash.into()),
        Token::Uint(U256::from_dec_str(&source_event_index.to_string()).unwrap()), // TODO: could this be done better?
    ])
    .into()
}

fn encode_data(
    destination_chain_id: &Uint256,
    commands_ids: &[KeccackHash],
    commands_types: &[String],
    commands_params: Vec<HexBinary>,
) -> HexBinary {
    let destination_chain_id =
        Token::Uint(U256::from_dec_str(&destination_chain_id.to_string()).unwrap());
    let commands_ids: Vec<Token> = commands_ids
        .iter()
        .map(|item| Token::FixedBytes(item.to_vec()))
        .collect();
    let commands_types: Vec<Token> = commands_types
        .iter()
        .map(|item| Token::String(item.into()))
        .collect();
    let commands_params: Vec<Token> = commands_params
        .into_iter()
        .map(|item| Token::Bytes(item.into()))
        .collect();

    ethabi::encode(&[
        destination_chain_id,
        Token::Array(commands_ids),
        Token::Array(commands_types),
        Token::Array(commands_params),
    ])
    .into()
}

fn build_unsigned_hash(data: &HexBinary) -> KeccackHash {
    let msg = Keccak256::digest(data.as_slice());

    let unsigned = [
        "\x19Ethereum Signed Message:\n%d%s".as_bytes(),
        msg.len().to_be_bytes().as_slice(),
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned)
        .as_slice()
        .try_into()
        .expect("Wrong length")
}
