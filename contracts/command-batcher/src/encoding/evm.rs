use std::{collections::HashMap, str::FromStr};

use axelar_wasm_std::Snapshot;
use connection_router::msg::Message;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use multisig::types::Signature;
use sha3::{Digest, Keccak256};

use crate::{
    error::ContractError,
    types::{Command, CommandBatch, CommandType, Data, Operator, Proof},
};

use super::traits;

impl TryFrom<Message> for Command {
    type Error = ContractError;

    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        Ok(Command {
            command_type: CommandType::ApproveContractCall, // TODO: this would change when other command types are supported
            command_params: command_params(
                msg.source_chain,
                msg.source_address,
                ethereum_types::Address::from_str(&msg.destination_address).map_err(|_| {
                    ContractError::InvalidMessage {
                        reason: "destination_address is not a valid EVM address".into(),
                    }
                })?,
                msg.payload_hash.as_slice().try_into().map_err(|_| {
                    ContractError::InvalidMessage {
                        reason: "payload_hash is not a valid keccak256 hash".into(),
                    }
                })?,
            ),
            id: command_id(msg.id),
        })
    }
}

pub struct Builder;
impl traits::Builder for Builder {
    fn build_batch(
        block_height: u64,
        messages: Vec<Message>,
        destination_chain_id: Uint256,
    ) -> Result<CommandBatch, ContractError> {
        let message_ids = messages.iter().map(|msg| msg.id.clone()).collect();

        let data = Data {
            destination_chain_id,
            commands: messages
                .into_iter()
                .map(|msg| msg.try_into())
                .collect::<Result<Vec<Command>, ContractError>>()?,
        };
        let encoded_data = Encoder::encode_data(&data);

        let id = batch_id(block_height, &encoded_data);
        let msg_to_sign = msg_to_sign(&encoded_data);

        Ok(CommandBatch {
            id,
            message_ids,
            data,
            msg_to_sign,
            multisig_session_id: None,
        })
    }

    fn build_proof(
        snapshot: Snapshot,
        signers: HashMap<String, Signature>,
        pub_keys: HashMap<String, multisig::types::PublicKey>,
    ) -> Result<Proof, ContractError> {
        let mut operators = snapshot
            .participants
            .iter()
            .map(|(_, participant)| {
                let pub_key = pub_keys
                    .get(&participant.address.to_string())
                    .ok_or(ContractError::PublicKeyNotFound {
                        participant: participant.address.to_string(),
                    })?
                    .into();

                Ok(Operator {
                    address: evm_address(pub_key)?,
                    weight: participant.weight.into(),
                    signature: signers.get(participant.address.as_str()).cloned(),
                })
            })
            .collect::<Result<Vec<Operator>, ContractError>>()?;
        operators.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(Proof {
            operators,
            threshold: snapshot.quorum.into(),
        })
    }
}

pub struct Encoder;

impl traits::Encoder for Encoder {
    fn encode_execute_data(data: &Data, proof: &Proof) -> HexBinary {
        ethabi::encode(&[
            Token::Bytes(Encoder::encode_data(data).into()),
            Token::Bytes(Encoder::encode_proof(proof).into()),
        ])
        .into()
    }
}

impl Encoder {
    pub fn encode_data(data: &Data) -> HexBinary {
        let destination_chain_id = Token::Uint(ethereum_types::U256::from_big_endian(
            &data.destination_chain_id.to_be_bytes(),
        ));

        let mut commands_ids: Vec<Token> = Vec::new();
        let mut commands_types: Vec<Token> = Vec::new();
        let mut commands_params: Vec<Token> = Vec::new();

        data.commands.iter().for_each(|command| {
            commands_ids.push(Token::FixedBytes(command.id.to_vec()));
            commands_types.push(Token::String(command.command_type.to_string()));
            commands_params.push(Token::Bytes(command.command_params.to_vec()));
        });

        ethabi::encode(&[
            destination_chain_id,
            Token::Array(commands_ids),
            Token::Array(commands_types),
            Token::Array(commands_params),
        ])
        .into()
    }

    pub fn encode_proof(proof: &Proof) -> HexBinary {
        let mut addresses: Vec<Token> = Vec::new();
        let mut weights: Vec<Token> = Vec::new();
        let mut signatures: Vec<Token> = Vec::new();

        proof.operators.iter().for_each(|operator| {
            addresses.push(Token::Address(ethereum_types::Address::from_slice(
                operator.address.as_slice(),
            )));
            weights.push(Token::Uint(ethereum_types::U256::from_big_endian(
                &operator.weight.to_be_bytes(),
            )));

            if let Some(signature) = &operator.signature {
                signatures.push(Token::Bytes(signature.into()));
            }
        });

        let threshold = Token::Uint(ethereum_types::U256::from_big_endian(
            &proof.threshold.to_be_bytes(),
        ));

        ethabi::encode(&[
            Token::Array(addresses),
            Token::Array(weights),
            threshold,
            Token::Array(signatures),
        ])
        .into()
    }
}

fn evm_address(pub_key: &[u8]) -> Result<HexBinary, ContractError> {
    let pub_key =
        PublicKey::from_sec1_bytes(pub_key).map_err(|e| ContractError::InvalidMessage {
            reason: e.to_string(),
        })?;
    let pub_key = pub_key.to_encoded_point(false);

    Ok(Keccak256::digest(&pub_key.as_bytes()[1..]).as_slice()[12..].into())
}

fn command_id(message_id: String) -> HexBinary {
    // TODO: we might need to change the command id format to match the one in core for migration purposes
    Keccak256::digest(message_id.as_bytes()).as_slice().into()
}

// TODO: This will make it incompatible with current version of destination chain gateways,
// they rely on tx hash and event index as well, but just to emit events
// https://github.com/axelarnetwork/axelar-cgp-solidity/blob/main/contracts/AxelarGateway.sol#L466
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

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::{nonempty, Participant};
    use cosmwasm_std::Timestamp;
    use ethabi::ParamType;

    use crate::test::test_data;

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

    pub fn decode_data(encoded_data: &HexBinary) -> Data {
        let tokens_array = &ethabi::decode(
            &[
                ParamType::Uint(256),
                ParamType::Array(Box::new(ParamType::FixedBytes(32))),
                ParamType::Array(Box::new(ParamType::String)),
                ParamType::Array(Box::new(ParamType::Bytes)),
            ],
            encoded_data,
        )
        .unwrap();

        let destination_chain_id;
        let mut commands = Vec::new();

        match (
            &tokens_array[0],
            &tokens_array[1],
            &tokens_array[2],
            &tokens_array[3],
        ) {
            (
                Token::Uint(chain_id),
                Token::Array(commands_ids_tokens),
                Token::Array(commands_types_tokens),
                Token::Array(commands_params_tokens),
            ) => {
                destination_chain_id = Uint256::from_be_bytes(chain_id.to_owned().into());
                commands_ids_tokens
                    .iter()
                    .zip(commands_types_tokens.iter())
                    .zip(commands_params_tokens.iter())
                    .for_each(|((id, command_type), command_params)| {
                        match (id, command_type, command_params) {
                            (
                                Token::FixedBytes(id),
                                Token::String(command_type),
                                Token::Bytes(command_params),
                            ) => {
                                let command = Command {
                                    id: id.to_owned().try_into().unwrap(),
                                    command_type: match command_type.as_str() {
                                        "approveContractCall" => CommandType::ApproveContractCall,
                                        _ => panic!("undecodable command type"),
                                    },
                                    command_params: HexBinary::from(command_params.to_owned()),
                                };

                                commands.push(command);
                            }
                            _ => panic!("Invalid data"),
                        }
                    });
            }
            _ => panic!("Invalid data"),
        }

        Data {
            destination_chain_id,
            commands,
        }
    }

    #[test]
    fn test_command_from_router_message() {
        let messages = test_data::messages();
        let router_message = messages.first().unwrap();

        let res = Command::try_from(router_message.to_owned());
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(
            res.id,
            HexBinary::from_hex("cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb73")
                .unwrap() // https://axelarscan.io/gmp/0xc8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f
        );
        assert_eq!(res.command_type, CommandType::ApproveContractCall);
        assert_eq!(
            decode_command_params(res.command_params),
            decode_command_params(
                decode_data(&test_data::encoded_data()).commands[0]
                    .command_params
                    .to_owned()
            )
        );
    }

    #[test]
    fn test_command_from_router_message_invalid_dest_addr() {
        let mut router_message = test_data::messages().first().unwrap().clone();
        router_message.destination_address = "invalid".into();

        let res = Command::try_from(router_message.to_owned());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidMessage {
                reason: "destination_address is not a valid EVM address".into()
            }
        );
    }

    #[test]
    fn test_command_from_router_message_invalid_payload_hash() {
        let mut router_message = test_data::messages().first().unwrap().clone();
        router_message.payload_hash =
            HexBinary::from_hex("df0e679e57348329e51e4337b7839882c29f21a3095a718c239f147b143ff8")
                .unwrap();

        let res = Command::try_from(router_message.to_owned());
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
        let messages = test_data::messages();
        let destination_chain_id = test_data::destination_chain_id();
        let test_data = decode_data(&test_data::encoded_data());

        let res =
            <Builder as traits::Builder>::build_batch(block_height, messages, destination_chain_id)
                .unwrap();

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

        test_data
            .commands
            .into_iter()
            .zip(res.data.commands.into_iter())
            .for_each(|(expected_command, command)| {
                assert_eq!(command.id, expected_command.id);
                assert_eq!(command.command_type, expected_command.command_type);
                assert_eq!(
                    decode_command_params(command.command_params),
                    decode_command_params(expected_command.command_params)
                );
            });

        assert_eq!(res.multisig_session_id, None);
    }

    #[test]
    fn test_proof() {
        let operators = test_data::operators();

        let timestamp: nonempty::Timestamp = Timestamp::from_nanos(1).try_into().unwrap();
        let height = nonempty::Uint64::try_from(test_data::block_height()).unwrap();

        let threshold = test_data::threshold();

        let mut participants = operators
            .iter()
            .map(|op| Participant {
                address: op.address.clone(),
                weight: op.weight.try_into().unwrap(),
            })
            .collect::<Vec<Participant>>();

        // Make a different sorting to make sure it gives same encoding regardless
        participants.sort_by(|a, b| Uint256::from(a.weight).cmp(&Uint256::from(b.weight)));

        let participants: nonempty::Vec<Participant> = participants.try_into().unwrap();

        let snapshot = Snapshot::new(timestamp.clone(), height.clone(), threshold, participants);

        let signers = operators
            .iter()
            .filter(|op| op.signature.is_some())
            .map(|op| (op.address.to_string(), op.signature.clone().unwrap()))
            .collect();

        let pub_keys = operators
            .iter()
            .map(|op| (op.address.to_string(), op.pub_key.clone()))
            .collect();

        let res = <Builder as traits::Builder>::build_proof(snapshot, signers, pub_keys).unwrap();
        assert_eq!(Encoder::encode_proof(&res), test_data::encoded_proof());
    }

    #[test]
    fn test_data_encode() {
        let encoded_data = test_data::encoded_data();
        let data = decode_data(&encoded_data);
        let res = Encoder::encode_data(&data);

        assert_eq!(res, encoded_data);
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

        let operator = evm_address(pub_key.as_slice()).unwrap();

        assert_eq!(operator, expected_address);
    }

    #[test]
    fn test_msg_to_sign() {
        let res = msg_to_sign(&test_data::encoded_data());
        let expected_msg = test_data::msg_to_sign();

        assert_eq!(res, expected_msg);
    }
}
