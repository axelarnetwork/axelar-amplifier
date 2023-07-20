use std::{collections::HashMap, fmt::Display, str::FromStr};

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use multisig::types::Signature;
use sha3::{Digest, Keccak256};

use crate::{
    error::ContractError,
    types::{CommandBatch, Proof},
};

use super::traits;

#[derive(Debug)]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: ethereum_types::Address,
    pub payload_hash: [u8; 32],
}

impl TryFrom<connection_router::msg::Message> for Message {
    type Error = ContractError;

    fn try_from(msg: connection_router::msg::Message) -> Result<Self, Self::Error> {
        Ok(Message {
            id: msg.id,
            source_address: msg.source_address,
            source_chain: msg.source_chain,
            destination_address: ethereum_types::Address::from_str(&msg.destination_address)
                .map_err(|_| ContractError::InvalidMessage {
                    reason: "destination_address is not a valid EVM address".into(),
                })?,
            payload_hash: msg.payload_hash.as_slice().try_into().map_err(|_| {
                ContractError::InvalidMessage {
                    reason: "payload_hash is not a valid keccak256 hash".into(),
                }
            })?,
        })
    }
}

// TODO: this would most likely change when other command types are supported
impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "approveContractCall")
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands_ids: Vec<[u8; 32]>,
    pub commands_types: Vec<String>,
    pub commands_params: Vec<HexBinary>,
}

impl Data {
    fn new(destination_chain_id: Uint256, messages: Vec<Message>) -> Self {
        let mut commands_ids: Vec<[u8; 32]> = Vec::new();
        let mut commands_types: Vec<String> = Vec::new();
        let mut commands_params: Vec<HexBinary> = Vec::new();

        for message in messages {
            let command_type = message.to_string();
            let command_id = command_id(message.id);
            let command_params = command_params(
                message.source_chain,
                message.source_address,
                message.destination_address,
                message.payload_hash,
            );

            commands_ids.push(command_id);
            commands_types.push(command_type);
            commands_params.push(command_params);
        }

        Data {
            destination_chain_id,
            commands_ids,
            commands_types,
            commands_params,
        }
    }

    fn encode(&self) -> HexBinary {
        let destination_chain_id = Token::Uint(
            ethereum_types::U256::from_dec_str(&self.destination_chain_id.to_string())
                .expect("violated invariant: Uint256 is not a valid EVM uint256"),
        );
        let commands_ids: Vec<Token> = self
            .commands_ids
            .iter()
            .map(|id| Token::FixedBytes(id.to_vec()))
            .collect();
        let commands_types: Vec<Token> = self
            .commands_types
            .iter()
            .map(|cmd| Token::String(cmd.into()))
            .collect();
        let commands_params: Vec<Token> = self
            .commands_params
            .iter()
            .map(|params| Token::Bytes(params.to_vec()))
            .collect();

        ethabi::encode(&[
            destination_chain_id,
            Token::Array(commands_ids),
            Token::Array(commands_types),
            Token::Array(commands_params),
        ])
        .into()
    }
}

impl Proof {
    fn encode(&self) -> HexBinary {
        let operators: Vec<Token> = self
            .operators
            .iter()
            .map(|operator| {
                Token::Address(ethereum_types::Address::from_slice(operator.as_slice()))
            })
            .collect();
        let weights: Vec<Token> = self
            .weights
            .iter()
            .map(|weight| {
                Token::Uint(
                    ethereum_types::U256::from_dec_str(&weight.to_string())
                        .expect("violated invariant: Uint256 is not a valid EVM uint256"),
                )
            })
            .collect();
        let quorum = Token::Uint(
            ethereum_types::U256::from_dec_str(&self.quorum.to_string())
                .expect("violated invariant: Uint256 is not a valid EVM uint256"),
        );
        let signatures: Vec<Token> = self
            .signatures
            .iter()
            .map(|signature| Token::Bytes(signature.to_vec()))
            .collect();

        ethabi::encode(&[
            Token::Array(operators),
            Token::Array(weights),
            quorum,
            Token::Array(signatures),
        ])
        .into()
    }
}

pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

fn evm_address(pub_key: &[u8]) -> HexBinary {
    let pub_key = PublicKey::from_sec1_bytes(pub_key)
        .expect("violated invariant: pub_key is not a valid secp256k1 public key");
    let pub_key = pub_key.to_encoded_point(false);

    Keccak256::digest(&pub_key.as_bytes()[1..]).as_slice()[12..].into()
}

impl<'a> traits::Proof<'a> for Proof {
    fn new(
        snapshot: Snapshot,
        signers: HashMap<String, Signature>,
        pub_keys: HashMap<String, multisig::types::PublicKey>,
    ) -> Self {
        let mut addresses: Vec<HexBinary> = Vec::new();
        let mut weights: Vec<Uint256> = Vec::new();
        let mut signatures: Vec<HexBinary> = Vec::new();

        let mut operators = snapshot
            .participants
            .iter()
            .map(|(_, participant)| {
                let pub_key = pub_keys
                    .get(&participant.address.to_string())
                    .expect("violated invariant: participant address not found in pub_keys")
                    .into();

                Operator {
                    address: evm_address(pub_key),
                    weight: participant.weight.into(),
                    signature: signers.get(participant.address.as_str()).cloned(),
                }
            })
            .collect::<Vec<Operator>>();
        operators.sort_by(|a, b| a.address.cmp(&b.address));

        for operator in operators {
            addresses.push(operator.address);
            weights.push(operator.weight);

            if let Some(signature) = operator.signature {
                signatures.push(signature.into());
            }
        }

        Proof {
            operators: addresses,
            weights,
            quorum: snapshot.quorum.into(),
            signatures,
        }
    }

    fn encode_execute_data(&self, data: &Data) -> HexBinary {
        let data_encoded = data.encode();
        let proof_encoded = self.encode();

        ethabi::encode(&[
            Token::Bytes(data_encoded.into()),
            Token::Bytes(proof_encoded.into()),
        ])
        .into()
    }
}

impl traits::CommandBatch for CommandBatch {
    fn new(block_height: u64, messages: Vec<Message>, destination_chain_id: Uint256) -> Self {
        let message_ids = messages.iter().map(|msg| msg.id.clone()).collect();

        let data = Data::new(destination_chain_id, messages);
        let encoded_data = data.encode();

        let id = batch_id(block_height, &encoded_data);
        let msg_to_sign = msg_to_sign(&encoded_data);

        Self {
            id,
            message_ids,
            data,
            msg_to_sign,
            multisig_session_id: None,
        }
    }
}

fn command_id(message_id: String) -> [u8; 32] {
    // TODO: we might need to change the command id format to match the one in core for migration purposes

    Keccak256::digest(message_id.as_bytes())
        .as_slice()
        .try_into()
        .expect("violated invariant: Keccak256 length is not 32 bytes")
}

// TODO: This will make it incompatible with current version of destination chain gateways,
// they rely on tx hash and event index as well, but just to emit events
// https://github.com/axelarnetwork/axelar-cgp-solidity/blob/main/contracts/AxelarGateway.sol#L428
fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: ethereum_types::Address,
    payload_hash: [u8; 32],
) -> HexBinary {
    ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::Address(destination_address),
        Token::FixedBytes(payload_hash.into()),
    ])
    .into()
}

fn batch_id(block_height: u64, data: &HexBinary) -> HexBinary {
    let mut id_hasher = Keccak256::new();

    id_hasher.update(block_height.to_be_bytes());
    id_hasher.update(data.as_slice());

    id_hasher.finalize().as_slice().into()
}

fn msg_to_sign(data: &HexBinary) -> HexBinary {
    let msg = Keccak256::digest(data.as_slice());

    let unsigned = [
        "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

#[cfg(test)]
mod test {
    use ethabi::ParamType;

    use crate::test::common::test_data;

    use super::*;

    fn decode_command_params<'a>(encoded_params: impl Into<Vec<u8>>) -> Vec<Token> {
        ethabi::decode(
            &[
                ParamType::String,
                ParamType::String,
                ParamType::Address,
                ParamType::FixedBytes(32),
            ],
            &encoded_params.into(),
        )
        .unwrap()
    }

    #[test]
    fn test_message_from_router_message() {
        let messages = test_data::messages();
        let router_message = messages.first().unwrap();

        let res = Message::try_from(router_message.to_owned());
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(res.id, router_message.id);
        assert_eq!(res.source_chain, router_message.source_chain);
        assert_eq!(res.source_address, router_message.source_address);
        assert_eq!(
            res.destination_address,
            ethereum_types::Address::from_str(&router_message.destination_address).unwrap()
        );
        assert_eq!(res.payload_hash, router_message.payload_hash);
    }

    #[test]
    fn test_message_from_router_message_invalid_dest_addr() {
        let mut router_message = test_data::messages().first().unwrap().clone();
        router_message.destination_address = "invalid".into();

        let res = Message::try_from(router_message.to_owned());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidMessage {
                reason: "destination_address is not a valid EVM address".into()
            }
        );
    }

    #[test]
    fn test_message_from_router_message_invalid_payload_hash() {
        let mut router_message = test_data::messages().first().unwrap().clone();
        router_message.payload_hash =
            HexBinary::from_hex("df0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143ff8")
                .unwrap();

        let res = Message::try_from(router_message.to_owned());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidMessage {
                reason: "payload_hash is not a valid keccak256 hash".into()
            }
        );
    }

    #[test]
    fn test_new_command_batch() {
        let block_height = test_data::block_height();
        let messages = test_data::messages()
            .into_iter()
            .map(|msg| msg.try_into())
            .collect::<Result<Vec<Message>, ContractError>>()
            .unwrap();
        let destination_chain_id = test_data::destination_chain_id();
        let test_data = test_data::decoded_data();

        let res: CommandBatch =
            traits::CommandBatch::new(block_height, messages, destination_chain_id);

        assert_eq!(
            res.message_ids,
            test_data::messages()
                .into_iter()
                .map(|msg| msg.id)
                .collect::<Vec<String>>()
        );
        assert_eq!(
            res.data.destination_chain_id,
            test_data.destination_chain_id
        );
        assert_eq!(res.data.commands_ids, test_data.commands_ids);
        assert_eq!(res.data.commands_types, test_data.commands_types);
        test_data
            .commands_params
            .iter()
            .enumerate()
            .for_each(|(i, params)| {
                assert_eq!(
                    decode_command_params(res.data.commands_params[i].to_owned()),
                    decode_command_params(params.to_owned())
                );
            });
        assert_eq!(res.multisig_session_id, None);
    }

    #[test]
    fn test_data_encode() {
        let data = test_data::decoded_data();
        let res = data.encode();

        assert_eq!(res, test_data::encoded_data());
    }

    #[test]
    fn test_command_id() {
        let res = command_id(test_data::messages()[0].id.clone());

        assert_eq!(
            HexBinary::from(res).to_hex(),
            "cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb73" // https://axelarscan.io/gmp/0xc8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f
        );
    }

    #[test]
    fn test_command_params() {
        let message: Message = test_data::messages()[0].clone().try_into().unwrap();

        let res = command_params(
            message.source_chain.clone(),
            message.source_address.clone(),
            message.destination_address,
            message.payload_hash,
        );

        assert_eq!(
            decode_command_params(res),
            decode_command_params(test_data::decoded_data().commands_params[0].to_owned())
        );
    }

    #[test]
    fn test_batch_id() {
        let block_height = test_data::block_height();
        let data = test_data::encoded_data();

        let res = batch_id(block_height, &data);
        let expected_id = test_data::batch_id();

        assert_eq!(res, expected_id);
    }

    #[test]
    fn test_evm_address() {
        let pub_key = test_data::pub_key();
        let expected_address = test_data::evm_address();

        let operator = evm_address(pub_key.as_slice());

        assert_eq!(operator, expected_address);
    }

    #[test]
    fn test_msg_to_sign() {
        let res = msg_to_sign(&test_data::encoded_data());
        let expected_msg = test_data::msg_to_sign();

        assert_eq!(res, expected_msg);
    }
}
