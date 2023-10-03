use std::str::FromStr;

use cosmwasm_std::{HexBinary, Uint256};
use ethabi::ethereum_types;
use ethabi::{short_signature, ParamType, Token};
use itertools::MultiUnzip;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use sha3::{Digest, Keccak256};

use axelar_wasm_std::operators::Operators;
use multisig::{key::Signature, msg::Signer};

use crate::{
    error::ContractError,
    state::WorkerSet,
    types::{CommandBatch, Operator},
};

use super::Data;

pub const GATEWAY_EXECUTE_FUNCTION_NAME: &str = "execute";

pub fn encode(data: &Data) -> HexBinary {
    let destination_chain_id = Token::Uint(ethabi::ethereum_types::U256::from_big_endian(
        &data.destination_chain_id.to_be_bytes(),
    ));

    let (commands_ids, commands_types, commands_params) = data
        .commands
        .iter()
        .map(|command| {
            (
                Token::FixedBytes(command.id.to_vec()),
                Token::String(command.ty.to_string()),
                Token::Bytes(command.params.to_vec()),
            )
        })
        .multiunzip();

    ethabi::encode(&[
        destination_chain_id,
        Token::Array(commands_ids),
        Token::Array(commands_types),
        Token::Array(commands_params),
    ])
    .into()
}

pub fn msg_digest(command_batch: &CommandBatch) -> HexBinary {
    let msg = Keccak256::digest(encode(&command_batch.data).as_slice());

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

pub fn encode_execute_data(
    command_batch: &CommandBatch,
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let signers = signers
        .into_iter()
        .map(|(signer, signature)| {
            let mut signature = signature;
            if let Some(Signature::Ecdsa(nonrecoverable)) = signature {
                signature = nonrecoverable
                    .to_recoverable(
                        command_batch.msg_digest().as_slice(),
                        &signer.pub_key,
                        add27,
                    )
                    .map(Signature::EcdsaRecoverable)
                    .ok();
            }

            (signer, signature)
        })
        .collect::<Vec<_>>();

    let param = ethabi::encode(&[
        Token::Bytes(encode(&command_batch.data).into()),
        Token::Bytes(encode_proof(quorum, signers)?.into()),
    ]);

    let input = ethabi::encode(&[Token::Bytes(param)]);

    let mut calldata = short_signature(GATEWAY_EXECUTE_FUNCTION_NAME, &[ParamType::Bytes]).to_vec();

    calldata.extend(input);

    Ok(calldata.into())
}

fn encode_proof(
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let mut operators = make_evm_operators_with_sigs(signers)?;
    operators.sort();

    let (addresses, weights, signatures): (Vec<_>, Vec<_>, Vec<_>) = operators
        .into_iter()
        .map(|op| {
            (
                Token::Address(ethereum_types::Address::from_slice(op.address.as_slice())),
                Token::Uint(ethereum_types::U256::from_big_endian(
                    &op.weight.to_be_bytes(),
                )),
                op.signature
                    .map(|sig| Token::Bytes(<Vec<u8>>::from(sig.as_ref()))),
            )
        })
        .multiunzip();

    let signatures = signatures.into_iter().flatten().collect();

    let quorum = Token::Uint(ethereum_types::U256::from_big_endian(&quorum.to_be_bytes()));

    Ok(ethabi::encode(&[
        Token::Array(addresses),
        Token::Array(weights),
        quorum,
        Token::Array(signatures),
    ])
    .into())
}

pub fn make_operators(worker_set: WorkerSet) -> Operators {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|signer| {
            (
                evm_address(signer.pub_key.as_ref())
                    .expect("couldn't convert pubkey to evm address"),
                signer.weight,
            )
        })
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    Operators {
        weights_by_addresses: operators,
        threshold: worker_set.threshold,
    }
}

fn make_evm_operators_with_sigs(
    signers_with_sigs: Vec<(Signer, Option<Signature>)>,
) -> Result<Vec<Operator>, ContractError> {
    axelar_wasm_std::utils::try_map(signers_with_sigs, |(signer, sig)| {
        make_evm_operator(signer).map(|op| {
            if let Some(sig) = sig {
                return op.with_signature(sig);
            }
            op
        })
    })
}

fn make_evm_operator(signer: Signer) -> Result<Operator, ContractError> {
    Ok(Operator {
        address: evm_address(signer.pub_key.as_ref())?,
        weight: signer.weight,
        signature: None,
    })
}

fn add27(recovery_byte: u8) -> u8 {
    recovery_byte + 27
}

pub fn transfer_operatorship_params(worker_set: &WorkerSet) -> Result<HexBinary, ContractError> {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|signer| {
            (
                evm_address(signer.pub_key.as_ref())
                    .expect("couldn't convert pubkey to evm address"),
                signer.weight,
            )
        })
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    let (addresses, weights): (Vec<Token>, Vec<Token>) = operators
        .iter()
        .map(|operator| {
            (
                Token::Address(ethereum_types::Address::from_slice(operator.0.as_slice())),
                Token::Uint(ethereum_types::U256::from_big_endian(
                    &operator.1.to_be_bytes(),
                )),
            )
        })
        .unzip();

    let quorum = Token::Uint(ethereum_types::U256::from_big_endian(
        &worker_set.threshold.to_be_bytes(),
    ));

    Ok(ethabi::encode(&[Token::Array(addresses), Token::Array(weights), quorum]).into())
}

fn evm_address(pub_key: &[u8]) -> Result<HexBinary, ContractError> {
    let pub_key =
        PublicKey::from_sec1_bytes(pub_key).map_err(|err| ContractError::InvalidPublicKey {
            reason: err.to_string(),
        })?;
    let pub_key = pub_key.to_encoded_point(false);

    Ok(Keccak256::digest(&pub_key.as_bytes()[1..]).as_slice()[12..].into())
}

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
) -> Result<HexBinary, ContractError> {
    let destination_address =
        ethereum_types::Address::from_str(&destination_address).map_err(|err| {
            ContractError::InvalidMessage {
                reason: format!("destination_address is not a valid EVM address: {}", err),
            }
        })?;
    let payload_hash: [u8; 32] =
        payload_hash
            .as_slice()
            .try_into()
            .map_err(|err| ContractError::InvalidMessage {
                reason: format!(
                    "payload_hash length is not a valid keccak256 hash length: {}",
                    err
                ),
            })?;
    Ok(ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::Address(destination_address),
        Token::FixedBytes(payload_hash.into()),
        Token::FixedBytes(vec![]), // TODO: Dummy data for now while Gateway is updated to not require these fields
        Token::Uint(ethereum_types::U256::zero()),
    ])
    .into())
}

#[cfg(test)]
mod test {
    use elliptic_curve::consts::U32;
    use ethers::types::Signature as EthersSignature;
    use generic_array::GenericArray;
    use hex::FromHex;
    use k256::ecdsa::Signature as K256Signature;

    use multisig::key::KeyType;

    use crate::{
        encoding::{CommandBatchBuilder, Encoder},
        test::test_data,
        types::{Command, CommandType},
    };

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
        let router_message = messages.first().unwrap().clone();

        let res = command_params(
            router_message.cc_id.chain.to_string(),
            router_message.source_address.to_string(),
            router_message.destination_address.to_string(),
            router_message.payload_hash,
        );
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(
            decode_command_params(res),
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
        router_message.destination_address = "invalid".parse().unwrap();

        let res = command_params(
            router_message.cc_id.chain.to_string(),
            router_message.source_address.to_string(),
            router_message.destination_address.to_string(),
            router_message.payload_hash,
        );
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

        let res = command_params(
            router_message.cc_id.chain.to_string(),
            router_message.source_address.to_string(),
            router_message.destination_address.to_string(),
            router_message.payload_hash,
        );
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
        let res = transfer_operatorship_params(&new_worker_set);
        assert!(res.is_ok());

        let tokens = decode_operator_transfer_command_params(res.unwrap());
        let mut signers: Vec<Signer> = new_worker_set.signers.into_iter().collect();
        signers.sort_by_key(|signer| evm_address(signer.pub_key.as_ref()).unwrap());
        let mut i = 0;
        for signer in signers {
            assert_eq!(
                tokens[0].clone().into_array().unwrap()[i],
                Token::Address(ethereum_types::Address::from_slice(
                    evm_address(signer.pub_key.as_ref())
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
        let mut builder = CommandBatchBuilder::new(destination_chain_id, Encoder::Abi);
        for msg in messages {
            builder.add_message(msg).unwrap();
        }

        let res = builder.build().unwrap();

        assert_eq!(
            res.message_ids,
            test_data::messages()
                .into_iter()
                .map(|msg| msg.cc_id.to_string())
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
        let mut builder =
            CommandBatchBuilder::new(test_data::chain_id_operator_transfer(), Encoder::Abi);
        let res = builder.add_new_worker_set(test_data::new_worker_set());
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

        let mut builder = CommandBatchBuilder::new(destination_chain_id, Encoder::Abi);
        for msg in messages {
            let res = builder.add_message(msg);
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
            encoder: Encoder::Abi,
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

        let res = batch.encode_execute_data(quorum, signers).unwrap();
        assert_eq!(res, test_data::execute_data());
    }

    #[test]
    fn test_data_encode() {
        let encoded_data = test_data::encoded_data();
        let data = decode_data(&encoded_data);
        let res = data.encode(Encoder::Abi);

        assert_eq!(res, encoded_data);
    }

    #[test]
    fn test_evm_address() {
        let op = test_data::operators().remove(0);
        let pub_key = op.pub_key;
        let expected_address = op.operator;

        let evm_address = evm_address(pub_key.as_ref()).unwrap();

        assert_eq!(evm_address, expected_address);
    }

    #[test]
    fn test_msg_to_sign() {
        let batch = CommandBatch {
            id: HexBinary::from_hex("00").unwrap().into(),
            message_ids: vec![],
            data: decode_data(&test_data::encoded_data()),
            encoder: Encoder::Abi,
        };

        let res = batch.msg_digest();
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

        let mut operators = make_evm_operators_with_sigs(signers).unwrap();
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

    #[test]
    fn should_convert_signature_to_recoverable() {
        let ethers_signature = EthersSignature::from_str("74ab5ec395cdafd861dec309c30f6cf8884fc9905eb861171e636d9797478adb60b2bfceb7db0a08769ed7a60006096d3e0f6d3783d125600ac6306180ecbc6f1b").unwrap();
        let pub_key =
            Vec::from_hex("03571a2dcec96eecc7950c9f36367fd459b8d334bac01ac153b7ed3dcf4025fc22")
                .unwrap();

        let digest = "6ac52b00f4256d98d53c256949288135c14242a39001d5fdfa564ea003ccaf92";

        let signature = {
            let mut r_bytes = [0u8; 32];
            let mut s_bytes = [0u8; 32];
            ethers_signature.r.to_big_endian(&mut r_bytes);
            ethers_signature.s.to_big_endian(&mut s_bytes);
            let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
            let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);

            K256Signature::from_scalars(*gar, *gas).unwrap()
        };

        let non_recoverable: Signature = (KeyType::Ecdsa, HexBinary::from(signature.to_vec()))
            .try_into()
            .unwrap();

        if let Signature::Ecdsa(non_recoverable) = non_recoverable {
            let recoverable = non_recoverable
                .to_recoverable(
                    HexBinary::from_hex(digest).unwrap().as_slice(),
                    &multisig::key::PublicKey::Ecdsa(HexBinary::from(pub_key.to_vec())),
                    add27,
                )
                .unwrap();

            assert_eq!(recoverable.as_ref(), ethers_signature.to_vec().as_slice());
        } else {
            panic!("Invalid signature type")
        }
    }
}
