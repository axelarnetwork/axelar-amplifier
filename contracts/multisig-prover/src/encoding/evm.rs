use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, short_signature, ParamType, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use sha3::{Digest, Keccak256};

use connection_router::msg::Message;
use multisig::msg::Signer;

use crate::{
    error::ContractError,
    types::{BatchID, Command, CommandBatch, CommandType, Operator},
};

const GATEWAY_EXECUTE_FUNCTION_NAME: &str = "execute";

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

impl TryFrom<Signer> for Operator {
    type Error = ContractError;

    fn try_from(signer: Signer) -> Result<Self, Self::Error> {
        Ok(Self {
            address: evm_address(signer.pub_key.as_ref())?,
            weight: signer.weight,
            signature: signer.signature,
        })
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
                .map(TryInto::try_into)
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

    pub fn encode_execute_data(
        &self,
        quorum: Uint256,
        signers: Vec<Signer>,
    ) -> Result<HexBinary, ContractError> {
        let param = ethabi::encode(&[
            Token::Bytes(self.data.encode().into()),
            Token::Bytes(self.encode_proof(quorum, signers)?.into()),
        ]);

        let input = ethabi::encode(&[Token::Bytes(param)]);

        let mut calldata =
            short_signature(GATEWAY_EXECUTE_FUNCTION_NAME, &[ParamType::Bytes]).to_vec();

        calldata.extend(input);

        Ok(calldata.into())
    }

    fn encode_proof(
        &self,
        quorum: Uint256,
        signers: Vec<Signer>,
    ) -> Result<HexBinary, ContractError> {
        let operators = sorted_operators(signers)?;

        let (addresses, weights, signatures) = operators.iter().fold(
            (vec![], vec![], vec![]),
            |(mut addresses, mut weights, mut signatures), operator| {
                addresses.push(Token::Address(ethereum_types::Address::from_slice(
                    operator.address.as_slice(),
                )));
                weights.push(Token::Uint(ethereum_types::U256::from_big_endian(
                    &operator.weight.to_be_bytes(),
                )));

                if let Some(signature) = &operator.signature {
                    signatures.push(Token::Bytes(<Vec<u8>>::from(signature.clone())));
                }

                (addresses, weights, signatures)
            },
        );

        let quorum = Token::Uint(ethereum_types::U256::from_big_endian(&quorum.to_be_bytes()));

        Ok(ethabi::encode(&[
            Token::Array(addresses),
            Token::Array(weights),
            quorum,
            Token::Array(signatures),
        ])
        .into())
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
        PublicKey::from_sec1_bytes(pub_key).map_err(|e| ContractError::InvalidPublicKey {
            reason: e.to_string(),
        })?;
    let pub_key = pub_key.to_encoded_point(false);

    Ok(Keccak256::digest(&pub_key.as_bytes()[1..]).as_slice()[12..].into())
}

fn sorted_operators(signers: Vec<Signer>) -> Result<Vec<Operator>, ContractError> {
    let mut operators = signers
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<Operator>, ContractError>>()?;
    operators.sort();

    Ok(operators)
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
                reason: "destination_address is not a valid EVM address: Invalid character 'i' at position 0".into()
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
                reason: "payload_hash length is not a valid keccak256 hash length: could not convert slice to array"
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
    fn test_batch_with_proof() {
        let messages = test_data::messages();
        let destination_chain_id = test_data::destination_chain_id();
        let operators = test_data::operators();
        let quorum = test_data::quorum();

        let batch = CommandBatch::new(messages, destination_chain_id).unwrap();

        let signers = operators
            .into_iter()
            .map(|op| Signer {
                address: op.address,
                weight: op.weight.into(),
                pub_key: op.pub_key,
                signature: op.signature,
            })
            .collect::<Vec<Signer>>();

        let execute_data = &batch.encode_execute_data(quorum, signers).unwrap();

        let tokens = ethabi::decode(
            &[ParamType::Bytes],
            &execute_data.as_slice()[4..], // Remove the function signature
        )
        .unwrap();

        let input = match tokens[0].clone() {
            Token::Bytes(input) => input,
            _ => panic!("Invalid proof"),
        };

        let tokens =
            ethabi::decode(&[ParamType::Bytes, ParamType::Bytes], input.as_slice()).unwrap();

        assert_eq!(
            execute_data.as_slice()[0..4],
            short_signature(GATEWAY_EXECUTE_FUNCTION_NAME, &[ParamType::Bytes])
        );

        match tokens[0].clone() {
            Token::Bytes(res) => {
                let res = decode_data(&res.into());
                let expected_data = decode_data(&test_data::encoded_data());

                assert_eq!(res.destination_chain_id, expected_data.destination_chain_id);
                assert_eq!(res.commands.len(), expected_data.commands.len());

                expected_data
                    .commands
                    .into_iter()
                    .zip(res.commands.into_iter())
                    .for_each(|(expected_command, command)| {
                        assert_eq!(command.id, expected_command.id);
                        assert_eq!(command.ty, expected_command.ty);
                        assert_eq!(
                            decode_command_params(command.params),
                            decode_command_params(expected_command.params)
                        );
                    });
            }
            _ => panic!("Invalid proof"),
        }

        match tokens[1].clone() {
            Token::Bytes(res) => {
                assert_eq!(HexBinary::from(res), test_data::encoded_proof());
            }
            _ => panic!("Invalid proof"),
        }
    }

    #[test]
    fn test_execute_data() {
        let operators = test_data::operators();
        let quorum = test_data::quorum();

        let batch = CommandBatch {
            id: HexBinary::from_hex("00").unwrap().into(),
            message_ids: vec![],
            data: decode_data(&test_data::encoded_data()),
        };

        let signers = operators
            .into_iter()
            .map(|op| Signer {
                address: op.address,
                weight: op.weight.into(),
                pub_key: op.pub_key,
                signature: op.signature,
            })
            .collect::<Vec<Signer>>();

        let res = batch.encode_execute_data(quorum, signers).unwrap();
        assert_eq!(res, test_data::execute_data());
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

    #[test]
    fn test_sorted_operators() {
        let mut operators = test_data::operators();

        let (operator1, operator2, operator3) = (
            operators.remove(0),
            operators.remove(0),
            operators.remove(0),
        );

        let signers = vec![
            Signer {
                address: operator2.address,
                weight: operator2.weight,
                pub_key: operator2.pub_key,
                signature: operator2.signature,
            },
            Signer {
                address: operator1.address,
                weight: operator1.weight,
                pub_key: operator1.pub_key,
                signature: operator1.signature,
            },
            Signer {
                address: operator3.address,
                weight: operator3.weight,
                pub_key: operator3.pub_key,
                signature: operator3.signature,
            },
        ];

        let operators = sorted_operators(signers).unwrap();

        assert_eq!(
            operators[0].address.cmp(&operators[1].address),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            operators[1].address.cmp(&operators[2].address),
            std::cmp::Ordering::Less
        );
    }
}
