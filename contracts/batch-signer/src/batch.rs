use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use ethabi::{ethereum_types, Token};
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
    pub hash_to_sign: KeccackHash,
    pub status: SigningStatus, // TODO: is this really needed?
}

impl CommandBatch {
    pub fn new(block_height: u64, messages: Vec<Message>, destination_chain_id: Uint256) -> Self {
        let (commands_ids, commands_types, commands_params) =
            build_commands_data(messages, destination_chain_id);

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
        .expect("violated invariant: Keccak256 length is not 32 bytes") // TODO: should we add a trait specific to panic violated invariants?
}

fn build_commands_data(
    messages: Vec<Message>,
    destination_chain_id: Uint256,
) -> (Vec<KeccackHash>, Vec<String>, Vec<HexBinary>) {
    let mut commands_ids: Vec<KeccackHash> = Vec::new();
    let mut commands_types: Vec<String> = Vec::new();
    let mut commands_params: Vec<HexBinary> = Vec::new();

    for message in messages {
        let command_type = message.to_string();

        let tx_hash = message.source_tx_hash();
        let event_index = message.source_event_index();

        let command_id = build_command_id(&tx_hash, &event_index, &destination_chain_id);

        commands_ids.push(command_id);
        commands_types.push(command_type);
        commands_params.push(encode_command_params(
            message.source_chain,
            message.source_address,
            message.destination_address,
            message.payload_hash,
            tx_hash,
            event_index,
        ));
    }

    (commands_ids, commands_types, commands_params)
}

fn build_command_id(tx_hash: &HexBinary, event_index: &Uint64, chain_id: &Uint256) -> KeccackHash {
    // TODO: is format required to be exactly like core? https://github.com/axelarnetwork/axelar-core/blob/4cb04c2925f2dec307afc3b7e94d7d254728cbeb/x/evm/types/types.go#L662
    let data = [
        tx_hash.as_slice(),
        &event_index.to_le_bytes(),
        chain_id
            .to_be_bytes()
            .iter()
            .skip_while(|x| *x == &0u8)
            .copied()
            .collect::<Vec<u8>>()
            .as_slice(),
    ]
    .concat();

    Keccak256::digest(data)
        .as_slice()
        .try_into()
        .expect("violated invariant: Keccak256 length is not 32 bytes")
}

fn encode_command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
    source_tx_hash: HexBinary,
    source_event_index: Uint64,
) -> HexBinary {
    ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::Address(ethereum_types::H160::from_str(destination_address.as_str()).unwrap()),
        Token::FixedBytes(payload_hash.into()),
        Token::FixedBytes(source_tx_hash.into()),
        Token::Uint(ethereum_types::U256::from(source_event_index.u64())),
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
    use super::*;

    #[test]
    fn test_new_batch() {
        // https://axelarscan.io/batch/ethereum/0304b99223f238f417cd015b724d32081a19cee49a41a839b73cd16ccaa538ab

        let block_height = 7593939;
        let destination_chain_id = 1u64.into();

        let messages = vec![
            Message {
                id: "c8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f-1".into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: "05a8AA0ed1e1bc598C23B415F67Cd774B530546C".into(),
                payload_hash: HexBinary::from_hex(
                    "df0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff8",
                )
                .unwrap(),
            },
            Message {
                id: "e7a7263a63ac449b4c6ce2a93accfae9ae49c1d96e3fa9c19cc417130bcfda22-1".into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: "05a8AA0ed1e1bc598C23B415F67Cd774B530546C".into(),
                payload_hash: HexBinary::from_hex(
                    "d8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a5",
                )
                .unwrap(),
            },
        ];

        let expected_batch = CommandBatch {
            id: hex::decode("0304b99223f238f417cd015b724d32081a19cee49a41a839b73cd16ccaa538ab").unwrap().try_into().unwrap(),
            commands_ids: vec![
                hex::decode("cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb73").unwrap().try_into().unwrap(),
                hex::decode("4ddf46ac2855e6614da7c654d224a58ad9eb9f567c45432c5120aa83a772a1e5").unwrap().try_into().unwrap(),
            ],
            encoded_data: HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000002cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb734ddf46ac2855e6614da7c654d224a58ad9eb9f567c45432c5120aa83a772a1e50000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cdf0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff8c8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783636343233613162343565313445614238423133323636354665624337456338364266634246343400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cd8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a5e7a7263a63ac449b4c6ce2a93accfae9ae49c1d96e3fa9c19cc417130bcfda2200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783636343233613162343565313445614238423133323636354665624337456338364266634246343400000000000000000000000000000000000000000000").unwrap(),
            hash_to_sign: hex::decode("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537").unwrap().try_into().unwrap(),
            status: SigningStatus::Signed,
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
