use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, Token};
use sha3::{Digest, Keccak256};

use crate::types::{KeccackHash, Message};

#[cw_serde]
pub struct CommandBatch {
    pub id: KeccackHash,
    pub commands_ids: Vec<KeccackHash>,
    pub encoded_data: HexBinary,
    pub hash_to_sign: KeccackHash,
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
        let hash_to_sign = build_hash_to_sign(&encoded_data);

        Self {
            id,
            commands_ids,
            encoded_data,
            hash_to_sign,
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
        .expect("violated invariant: Keccak256 length is not 32 bytes") // TODO: should we add a trait specific to panic violated invariants?
}

fn build_commands_data(messages: Vec<Message>) -> (Vec<KeccackHash>, Vec<String>, Vec<HexBinary>) {
    let mut commands_ids: Vec<KeccackHash> = Vec::new();
    let mut commands_types: Vec<String> = Vec::new();
    let mut commands_params: Vec<HexBinary> = Vec::new();

    for message in messages {
        let command_type = message.to_string();

        let command_id = build_command_id(message.id);

        commands_ids.push(command_id);
        commands_types.push(command_type);
        commands_params.push(encode_command_params(
            message.source_chain,
            message.source_address,
            message.destination_address,
            message.payload_hash,
        ));
    }

    (commands_ids, commands_types, commands_params)
}

fn build_command_id(message_id: String) -> KeccackHash {
    // TODO: we might need to change the command id format to match the one in core for migration purposes

    Keccak256::digest(message_id.as_bytes())
        .as_slice()
        .try_into()
        .expect("violated invariant: Keccak256 length is not 32 bytes")
}

fn encode_command_params(
    source_chain: String,
    source_address: String,
    destination_address: ethereum_types::Address,
    payload_hash: KeccackHash,
) -> HexBinary {
    ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::Address(destination_address),
        Token::FixedBytes(payload_hash.into()),
    ])
    .into()
}

fn encode_data(
    destination_chain_id: &Uint256,
    commands_ids: &[KeccackHash],
    commands_types: &[String],
    commands_params: Vec<HexBinary>,
) -> HexBinary {
    let destination_chain_id = Token::Uint(
        ethereum_types::U256::from_dec_str(&destination_chain_id.to_string())
            .expect("violated invariant: Uint256 is not a valid EVM uint256"),
    );
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

fn build_hash_to_sign(data: &HexBinary) -> KeccackHash {
    let msg = Keccak256::digest(data.as_slice());

    let unsigned = [
        "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned)
        .as_slice()
        .try_into()
        .expect("violated invariant: Keccak256 length is not 32 bytes")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_new_batch() {
        let block_height = 7593939;
        let destination_chain_id = 1u64.into();

        let messages = vec![
            Message {
                id: "c8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f-1".into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: ethereum_types::Address::from_str(
                    "05a8AA0ed1e1bc598C23B415F67Cd774B530546C",
                )
                .unwrap(),
                payload_hash: HexBinary::from_hex(
                    "df0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff8",
                )
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
            },
            Message {
                id: "e7a7263a63ac449b4c6ce2a93accfae9ae49c1d96e3fa9c19cc417130bcfda22-1".into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: ethereum_types::Address::from_str(
                    "05a8AA0ed1e1bc598C23B415F67Cd774B530546C",
                )
                .unwrap(),
                payload_hash: HexBinary::from_hex(
                    "d8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a5",
                )
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
            },
        ];

        let expected_batch = CommandBatch {
            id: hex::decode("21871578588b38282f449232db51a47b9e22289ddf3f7052e03c7b464ab1b84b").unwrap().try_into().unwrap(),
            commands_ids: vec![
                hex::decode("3ecc0a06d74c403d85a4953742287ab3bed54be997314a2bbd30f3c5cd3666fa").unwrap().try_into().unwrap(),
                hex::decode("96c1b646d876886426e9e9dd5e4acc96cd87918b0d2685f7e6e5881ca35a6630").unwrap().try_into().unwrap(),
            ],
            encoded_data: HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000023ecc0a06d74c403d85a4953742287ab3bed54be997314a2bbd30f3c5cd3666fa96c1b646d876886426e9e9dd5e4acc96cd87918b0d2685f7e6e5881ca35a66300000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cdf0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff80000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307836363432336131623435653134456142384231333236363546656243374563383642666342463434000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cd8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a50000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783636343233613162343565313445614238423133323636354665624337456338364266634246343400000000000000000000000000000000000000000000").unwrap(),
            hash_to_sign: hex::decode("3531ca948047f8f391f1f3e768bd5e47e372d19663c4408e0d5a1fd88d1af8f0").unwrap().try_into().unwrap(),
        };

        let batch = CommandBatch::new(block_height, messages, destination_chain_id);

        assert_eq!(batch.id, expected_batch.id);
        assert_eq!(batch.commands_ids, expected_batch.commands_ids);
        assert_eq!(batch.encoded_data, expected_batch.encoded_data);
        assert_eq!(batch.hash_to_sign, expected_batch.hash_to_sign);
    }

    #[test]
    fn test_hash_to_sign() {
        let data = HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000001ec78d9c22c08bb9f0ecd5d95571ae83e3f22219c5a9278c3270691d50abfd91b000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000096d696e74546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000014141540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000063fc2ad3d021a4d7e64323529a55a9442c444da00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000270f").unwrap();
        let expected =
            "e7bce8f57491e71212d930096bacf9288c711e5f27200946edd570e3a93546bf".to_string();
        let actual = hex::encode(build_hash_to_sign(&data));

        assert_eq!(actual, expected);
    }
}
