use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{ethereum_types, short_signature, ParamType, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use sha3::{Digest, Keccak256};

use connection_router::msg::Message;
use multisig::{key::Signature, msg::Signer};

use crate::{
    error::ContractError,
    msg::EncodingScheme,
    state::WorkerSet,
    types::{BatchID, Command, CommandBatch, CommandType, Operator},
};

use super::abi;

fn make_command(msg: Message, encoding_scheme: EncodingScheme) -> Result<Command, ContractError> {
    Ok(Command {
        ty: CommandType::ApproveContractCall, // TODO: this would change when other command types are supported
        params: match encoding_scheme {
            EncodingScheme::Abi => abi::command_params(
                msg.source_chain,
                msg.source_address,
                msg.destination_address,
                msg.payload_hash,
            )?,
            EncodingScheme::Bcs => todo!(),
        },
        id: command_id(msg.id),
    })
}

fn make_transfer_operatorship(
    worker_set: WorkerSet,
    encoding_scheme: EncodingScheme,
) -> Result<Command, ContractError> {
    let params = transfer_operatorship_params(&worker_set, encoding_scheme)?;
    Ok(Command {
        ty: CommandType::TransferOperatorship,
        params,
        id: worker_set.hash(),
    })
}

pub struct CommandBatchBuilder {
    message_ids: Vec<String>,
    new_worker_set: Option<WorkerSet>,
    commands: Vec<Command>,
    destination_chain_id: Uint256,
}

impl CommandBatchBuilder {
    pub fn new(destination_chain_id: Uint256) -> Self {
        Self {
            message_ids: vec![],
            new_worker_set: None,
            commands: vec![],
            destination_chain_id,
        }
    }

    pub fn add_message(
        &mut self,
        msg: Message,
        encoding_scheme: EncodingScheme,
    ) -> Result<(), ContractError> {
        self.message_ids.push(msg.id.clone());
        self.commands.push(make_command(msg, encoding_scheme)?);
        Ok(())
    }

    pub fn add_new_worker_set(
        &mut self,
        worker_set: WorkerSet,
        encoding_scheme: EncodingScheme,
    ) -> Result<(), ContractError> {
        self.new_worker_set = Some(worker_set.clone());
        self.commands
            .push(make_transfer_operatorship(worker_set, encoding_scheme)?);
        Ok(())
    }

    pub fn build(self) -> Result<CommandBatch, ContractError> {
        let data = Data {
            destination_chain_id: self.destination_chain_id,
            commands: self.commands,
        };

        let id = BatchID::new(&self.message_ids, self.new_worker_set);

        Ok(CommandBatch {
            id,
            message_ids: self.message_ids,
            data,
        })
    }
}

impl CommandBatch {
    pub fn msg_to_sign(&self, encoding_scheme: EncodingScheme) -> HexBinary {
        match encoding_scheme {
            EncodingScheme::Abi => abi::msg_to_sign(self),
            EncodingScheme::Bcs => todo!(),
        }
    }

    pub fn encode_execute_data(
        &self,
        quorum: Uint256,
        signers: Vec<(Signer, Option<Signature>)>,
        encoding_scheme: EncodingScheme,
    ) -> Result<HexBinary, ContractError> {
        match encoding_scheme {
            EncodingScheme::Abi => abi::encode_execute_data(self, quorum, signers),
            EncodingScheme::Bcs => todo!(),
        }
    }
}

fn transfer_operatorship_params(
    worker_set: &WorkerSet,
    encoding_scheme: EncodingScheme,
) -> Result<HexBinary, ContractError> {
    match encoding_scheme {
        EncodingScheme::Abi => abi::transfer_operatorship_params(worker_set),
        EncodingScheme::Bcs => {
            todo!()
        }
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands: Vec<Command>,
}

impl Data {
    pub fn encode(&self, encoding_scheme: EncodingScheme) -> HexBinary {
        match encoding_scheme {
            EncodingScheme::Abi => abi::encode(self),
            EncodingScheme::Bcs => todo!(),
        }
    }
}

fn command_id(message_id: String) -> HexBinary {
    // TODO: we might need to change the command id format to match the one in core for migration purposes
    Keccak256::digest(message_id.as_bytes()).as_slice().into()
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
    fn decode_operator_transfer_command_params<'a>(
        encoded_params: impl Into<Vec<u8>>,
    ) -> Vec<Token> {
        ethabi::decode(
            &[
                ParamType::Array(Box::new(ParamType::Address)),
                ParamType::Array(Box::new(ParamType::Uint(32))),
                ParamType::Uint(32),
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
                                    "transferOperatorship" => CommandType::TransferOperatorship,
                                    &_ => panic!("undecodable command type"),
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

        let res = make_command(router_message.to_owned(), EncodingScheme::Abi);
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

        let res = make_command(router_message.to_owned(), EncodingScheme::Abi);
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

        let res = make_command(router_message.to_owned(), EncodingScheme::Abi);
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidMessage {
                reason: "payload_hash length is not a valid keccak256 hash length: could not convert slice to array"
                    .into()
            }
        );
    }

    #[test]
    fn test_command_operator_transfer() {
        let new_worker_set = test_data::new_worker_set();
        let res = make_transfer_operatorship(new_worker_set.clone(), EncodingScheme::Abi);
        assert!(res.is_ok());

        let tokens = decode_operator_transfer_command_params(res.unwrap().params);
        let mut signers: Vec<Signer> = new_worker_set.signers.into_iter().collect();
        signers.sort_by_key(|signer| abi::evm_address(signer.pub_key.as_ref()).unwrap());
        let mut i = 0;
        for signer in signers {
            assert_eq!(
                tokens[0].clone().into_array().unwrap()[i],
                Token::Address(ethereum_types::Address::from_slice(
                    abi::evm_address(signer.pub_key.as_ref())
                        .expect("couldn't convert pubkey to evm address")
                        .as_slice()
                ))
            );

            assert_eq!(
                tokens[1].clone().into_array().unwrap()[i],
                Token::Uint(ethereum_types::U256::from_big_endian(
                    &signer.weight.to_be_bytes()
                ))
            );
            i = i + 1;
        }
        assert_eq!(
            tokens[2],
            Token::Uint(ethereum_types::U256::from_big_endian(
                &new_worker_set.threshold.to_be_bytes()
            ))
        );
    }

    #[test]
    fn test_new_command_batch() {
        let messages = test_data::messages();
        let destination_chain_id = test_data::destination_chain_id();
        let test_data = decode_data(&test_data::encoded_data());
        let mut builder = CommandBatchBuilder::new(destination_chain_id);
        for msg in messages {
            builder.add_message(msg, EncodingScheme::Abi).unwrap();
        }

        let res = builder.build().unwrap();

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
    fn test_new_command_batch_with_operator_transfer() {
        let test_data = decode_data(&test_data::encoded_data_with_operator_transfer());
        let mut builder = CommandBatchBuilder::new(test_data::chain_id_operator_transfer());
        let res = builder.add_new_worker_set(test_data::new_worker_set(), EncodingScheme::Abi);
        assert!(res.is_ok());
        let res = builder.build();
        assert!(res.is_ok());
        assert_eq!(res.unwrap().data, test_data);
    }

    #[test]
    fn test_batch_with_proof() {
        let messages = test_data::messages();
        let destination_chain_id = test_data::destination_chain_id();
        let operators = test_data::operators();
        let quorum = test_data::quorum();

        let mut builder = CommandBatchBuilder::new(destination_chain_id);
        for msg in messages {
            let res = builder.add_message(msg, EncodingScheme::Abi);
            assert!(res.is_ok());
        }
        let batch = builder.build().unwrap();

        let signers = operators
            .into_iter()
            .map(|op| {
                (
                    Signer {
                        address: op.address,
                        weight: op.weight.into(),
                        pub_key: op.pub_key,
                    },
                    op.signature,
                )
            })
            .collect::<Vec<(Signer, Option<Signature>)>>();

        let execute_data = &batch
            .encode_execute_data(quorum, signers, EncodingScheme::Abi)
            .unwrap();

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
            short_signature(abi::GATEWAY_EXECUTE_FUNCTION_NAME, &[ParamType::Bytes])
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
            .map(|op| {
                (
                    Signer {
                        address: op.address,
                        weight: op.weight.into(),
                        pub_key: op.pub_key,
                    },
                    op.signature,
                )
            })
            .collect::<Vec<(Signer, Option<Signature>)>>();

        let res = batch
            .encode_execute_data(quorum, signers, EncodingScheme::Abi)
            .unwrap();
        assert_eq!(res, test_data::execute_data());
    }

    #[test]
    fn test_data_encode() {
        let encoded_data = test_data::encoded_data();
        let data = decode_data(&encoded_data);
        let res = data.encode(EncodingScheme::Abi);

        assert_eq!(res, encoded_data);
    }

    #[test]
    fn test_batch_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<String> = messages.iter().map(|msg| msg.id.clone()).collect();

        message_ids.sort();
        let res = BatchID::new(&message_ids, None);

        message_ids.reverse();
        let res2 = BatchID::new(&message_ids, None);

        assert_eq!(res, res2);
    }

    #[test]
    fn test_evm_address() {
        let pub_key = test_data::pub_key();
        let expected_address = test_data::evm_address();

        let operator = abi::evm_address(pub_key.as_slice()).unwrap();

        assert_eq!(operator, expected_address);
    }

    #[test]
    fn test_msg_to_sign() {
        let batch = CommandBatch {
            id: HexBinary::from_hex("00").unwrap().into(),
            message_ids: vec![],
            data: decode_data(&test_data::encoded_data()),
        };

        let res = batch.msg_to_sign(EncodingScheme::Abi);
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
            (
                Signer {
                    address: operator2.address,
                    weight: operator2.weight,
                    pub_key: operator2.pub_key,
                },
                operator2.signature,
            ),
            (
                Signer {
                    address: operator1.address,
                    weight: operator1.weight,
                    pub_key: operator1.pub_key,
                },
                operator1.signature,
            ),
            (
                Signer {
                    address: operator3.address,
                    weight: operator3.weight,
                    pub_key: operator3.pub_key,
                },
                operator3.signature,
            ),
        ];

        let mut operators = abi::make_operators(signers).unwrap();
        operators.sort();

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
