use std::{collections::HashMap, str::FromStr};

use axelar_wasm_std::Snapshot;
use connection_router::msg::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use multisig::types::Signature;
use sha3::{Digest, Keccak256};

use crate::{
    error::ContractError,
    types::{BatchID, Command, CommandBatch, CommandType, Operator, Proof},
};

impl TryFrom<Message> for Command {
    type Error = ContractError;

    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        Ok(Command {
            ty: CommandType::ApproveContractCall, // TODO: this would change when other command types are supported
            params: command_params(
                msg.source_chain,
                msg.source_address,
                ethereum_types::Address::from_str(&msg.destination_address).map_err(|e| {
                    ContractError::InvalidMessage {
                        reason: format!("destination_address is not a valid EVM address: {}", e),
                    }
                })?,
                msg.payload_hash.as_slice().try_into().map_err(|e| {
                    ContractError::InvalidMessage {
                        reason: format!(
                            "payload_hash length is not a valid keccak256 hash length: {}",
                            e
                        ),
                    }
                })?,
            ),
            id: command_id(msg.id),
        })
    }
}

impl BatchID {
    pub fn new(message_ids: &[String]) -> BatchID {
        let mut message_ids = message_ids
            .iter()
            .map(|id| id.as_bytes())
            .collect::<Vec<&[u8]>>();
        message_ids.sort();

        Keccak256::digest(message_ids.concat()).as_slice().into()
    }
}

impl CommandBatch {
    pub fn new(
        messages: Vec<Message>,
        destination_chain_id: Uint256,
    ) -> Result<Self, ContractError> {
        let message_ids: Vec<String> = messages.iter().map(|msg| msg.id.clone()).collect();

        let data = Data {
            destination_chain_id,
            commands: messages
                .into_iter()
                .map(|msg| msg.try_into())
                .collect::<Result<Vec<Command>, ContractError>>()?,
        };

        let id = BatchID::new(&message_ids);

        Ok(Self {
            id,
            message_ids,
            data,
        })
    }

    pub fn msg_to_sign(&self) -> HexBinary {
        let msg = Keccak256::digest(self.data.encode().as_slice());

        // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
        let unsigned = [
            "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
            msg.as_slice(),
        ]
        .concat();

        Keccak256::digest(unsigned).as_slice().into()
    }
}

impl Proof {
    pub fn new(
        snapshot: Snapshot,
        signers: HashMap<String, Signature>,
        pub_keys: HashMap<String, multisig::types::PublicKey>,
    ) -> Result<Proof, ContractError> {
        let mut operators = snapshot
            .participants
            .into_iter()
            .map(|(address, participant)| {
                let pub_key = pub_keys
                    .get(&address)
                    .ok_or(ContractError::PublicKeyNotFound {
                        participant: address,
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

    pub fn encode(&self) -> HexBinary {
        let (addresses, weights, signatures) = self.operators.iter().fold(
            (vec![], vec![], vec![]),
            |(mut addresses, mut weights, mut signatures), operator| {
                addresses.push(Token::Address(ethereum_types::Address::from_slice(
                    operator.address.as_slice(),
                )));
                weights.push(Token::Uint(ethereum_types::U256::from_big_endian(
                    &operator.weight.to_be_bytes(),
                )));

                if let Some(signature) = &operator.signature {
                    signatures.push(Token::Bytes(signature.into()));
                }

                (addresses, weights, signatures)
            },
        );

        let threshold = Token::Uint(ethereum_types::U256::from_big_endian(
            &self.threshold.to_be_bytes(),
        ));

        ethabi::encode(&[
            Token::Array(addresses),
            Token::Array(weights),
            threshold,
            Token::Array(signatures),
        ])
        .into()
    }

    pub fn encode_execute_data(&self, data: &Data) -> HexBinary {
        ethabi::encode(&[
            Token::Bytes(data.encode().into()),
            Token::Bytes(self.encode().into()),
        ])
        .into()
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands: Vec<Command>,
}

impl Data {
    pub fn encode(&self) -> HexBinary {
        let destination_chain_id = Token::Uint(ethereum_types::U256::from_big_endian(
            &self.destination_chain_id.to_be_bytes(),
        ));

        let (commands_ids, commands_types, commands_params) = self.commands.iter().fold(
            (vec![], vec![], vec![]),
            |(mut commands_ids, mut commands_types, mut commands_params), command| {
                commands_ids.push(Token::FixedBytes(command.id.to_vec()));
                commands_types.push(Token::String(command.ty.to_string()));
                commands_params.push(Token::Bytes(command.params.to_vec()));
                (commands_ids, commands_types, commands_params)
            },
        );

        ethabi::encode(&[
            destination_chain_id,
            Token::Array(commands_ids),
            Token::Array(commands_types),
            Token::Array(commands_params),
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
        Token::FixedBytes(vec![]), // TODO: Dummy data for now while Gateway is updated to not require these fields
        Token::Uint(ethereum_types::U256::zero()),
    ])
    .into()
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
                    .for_each(|((id, ty), params)| match (id, ty, params) {
                        (Token::FixedBytes(id), Token::String(ty), Token::Bytes(params)) => {
                            let command = Command {
                                id: id.to_owned().try_into().unwrap(),
                                ty: match ty.as_str() {
                                    "approveContractCall" => CommandType::ApproveContractCall,
                                    _ => panic!("undecodable command type"),
                                },
                                params: HexBinary::from(params.to_owned()),
                            };

                            commands.push(command);
                        }
                        _ => panic!("Invalid data"),
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
        assert_eq!(res.ty, CommandType::ApproveContractCall);
        assert_eq!(
            decode_command_params(res.params),
            decode_command_params(
                decode_data(&test_data::encoded_data()).commands[0]
                    .params
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
                reason: "destination_address is not a valid EVM address: invalid character: i at index 0".into()
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
                reason:
                    "payload_hash length is not a valid keccak256 hash length: could not convert slice to array"
                        .into()
            }
        );
    }

    #[test]
    fn test_new_command_batch() {
        let messages = test_data::messages();
        let destination_chain_id = test_data::destination_chain_id();
        let test_data = decode_data(&test_data::encoded_data());

        let res = CommandBatch::new(messages, destination_chain_id).unwrap();

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
                assert_eq!(command.ty, expected_command.ty);
                assert_eq!(
                    decode_command_params(command.params),
                    decode_command_params(expected_command.params)
                );
            });
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

        let res = Proof::new(snapshot, signers, pub_keys).unwrap();
        assert_eq!(res.encode(), test_data::encoded_proof());
    }

    #[test]
    fn test_data_encode() {
        let encoded_data = test_data::encoded_data();
        let data = decode_data(&encoded_data);
        let res = data.encode();

        assert_eq!(res, encoded_data);
    }

    #[test]
    fn test_batch_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<String> = messages.iter().map(|msg| msg.id.clone()).collect();

        message_ids.sort();
        let res = BatchID::new(&message_ids);

        message_ids.reverse();
        let res2 = BatchID::new(&message_ids);

        assert_eq!(res, res2);
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
        let batch = CommandBatch {
            id: HexBinary::from_hex("00").unwrap().into(),
            message_ids: vec![],
            data: decode_data(&test_data::encoded_data()),
        };

        let res = batch.msg_to_sign();
        let expected_msg = test_data::msg_to_sign();

        assert_eq!(res, expected_msg);
    }
}
