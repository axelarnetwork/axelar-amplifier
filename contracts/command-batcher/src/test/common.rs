use crate::encoding::Data;
use connection_router::msg::Message;
use cosmwasm_std::{HexBinary, Uint256, Uint64};
use ethabi::{ParamType, Token};

pub mod test_data {
    use super::*;

    fn legacy_cmd_id_input(
        source_transaction: HexBinary,
        source_event_index: Uint64,
        chain_id: Uint256,
    ) -> String {
        let data = [
            source_transaction.as_slice(),
            &source_event_index.to_le_bytes(),
            chain_id
                .to_be_bytes()
                .iter()
                .skip_while(|x| *x == &0u8)
                .copied()
                .collect::<Vec<u8>>()
                .as_slice(),
        ]
        .concat();

        unsafe { String::from_utf8_unchecked(data) }
    }

    pub fn messages() -> Vec<Message> {
        vec![
            Message {
                // command_id = cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb73,
                id: legacy_cmd_id_input(
                    HexBinary::from_hex(
                        "c8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f",
                    )
                    .unwrap(),
                    Uint64::one(),
                    destination_chain_id(),
                )
                .into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: "05a8AA0ed1e1bc598C23B415F67Cd774B530546C".to_string(),
                destination_chain: "Ethereum".to_string(),
                payload_hash: HexBinary::from_hex(
                    "df0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff8",
                )
                .unwrap(),
            },
            Message {
                // command_id = 4ddf46ac2855e6614da7c654d224a58ad9eb9f567c45432c5120aa83a772a1e5,
                id: legacy_cmd_id_input(
                    HexBinary::from_hex(
                        "e7a7263a63ac449b4c6ce2a93accfae9ae49c1d96e3fa9c19cc417130bcfda22",
                    )
                    .unwrap(),
                    Uint64::one(),
                    destination_chain_id(),
                )
                .into(),
                source_chain: "Polygon".into(),
                source_address: "0x66423a1b45e14EaB8B132665FebC7Ec86BfcBF44".into(),
                destination_address: "05a8AA0ed1e1bc598C23B415F67Cd774B530546C".to_string(),
                destination_chain: "Ethereum".to_string(),
                payload_hash: HexBinary::from_hex(
                    "d8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a5",
                )
                .unwrap(),
            },
        ]
    }

    pub fn block_height() -> u64 {
        7593939
    }

    pub fn destination_chain_id() -> Uint256 {
        Uint256::one()
    }

    pub fn batch_id() -> HexBinary {
        HexBinary::from_hex("0304b99223f238f417cd015b724d32081a19cee49a41a839b73cd16ccaa538ab")
            .unwrap()
    }

    pub fn pub_key() -> HexBinary {
        HexBinary::from_hex("03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d")
            .unwrap()
    }

    pub fn evm_address() -> HexBinary {
        HexBinary::from_hex("01212E8f3996651D6978147E76aA1f36C34b6556").unwrap()
    }

    pub fn encoded_data() -> HexBinary {
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000002cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb734ddf46ac2855e6614da7c654d224a58ad9eb9f567c45432c5120aa83a772a1e50000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cdf0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143f9ff8c8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783636343233613162343565313445614238423133323636354665624337456338364266634246343400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000005a8aa0ed1e1bc598c23b415f67cd774b530546cd8f619df9786ea29e466d37c846576a49080089909bf228c19458739606341a5e7a7263a63ac449b4c6ce2a93accfae9ae49c1d96e3fa9c19cc417130bcfda2200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783636343233613162343565313445614238423133323636354665624337456338364266634246343400000000000000000000000000000000000000000000").unwrap()
    }

    pub fn decoded_data() -> crate::encoding::Data {
        let tokens_array = &ethabi::decode(
            &[
                ParamType::Uint(256),
                ParamType::Array(Box::new(ParamType::FixedBytes(32))),
                ParamType::Array(Box::new(ParamType::String)),
                ParamType::Array(Box::new(ParamType::Bytes)),
            ],
            &encoded_data(),
        )
        .unwrap();

        let destination_chain_id;
        let mut commands_ids = Vec::new();
        let mut commands_types = Vec::new();
        let mut commands_params = Vec::new();

        if let Token::Uint(chain_id) = &tokens_array[0] {
            destination_chain_id = Uint256::from_be_bytes(chain_id.to_owned().into());
        } else {
            panic!("Invalid destination chain id");
        }
        if let Token::Array(tokens) = &tokens_array[1] {
            for token in tokens {
                if let Token::FixedBytes(bytes) = token {
                    commands_ids.push(bytes.to_owned().try_into().unwrap());
                }
            }
        }
        if let Token::Array(tokens) = &tokens_array[2] {
            for token in tokens {
                if let Token::String(string) = token {
                    commands_types.push(string.to_owned());
                }
            }
        }
        if let Token::Array(tokens) = &tokens_array[3] {
            for token in tokens {
                if let Token::Bytes(bytes) = token {
                    commands_params.push(bytes.to_owned().into());
                }
            }
        }

        Data {
            destination_chain_id,
            commands_ids,
            commands_types,
            commands_params,
        }
    }

    pub fn msg_to_sign() -> HexBinary {
        HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
            .unwrap()
    }
}
