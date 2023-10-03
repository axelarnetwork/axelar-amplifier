use std::convert::identity;

use axelar_wasm_std::operators::Operators;
use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};

use crate::{error::ContractError, state::WorkerSet};

use itertools::Itertools;
use multisig::{key::Signature, msg::Signer};

use crate::types::{CommandBatch, Operator};

use super::Data;
use sha3::{Digest, Keccak256};

// TODO: all of the public functions in this file should be moved to a trait,
// that has an abi and bcs implementation (and possibly others)

pub fn make_operators(worker_set: WorkerSet) -> Operators {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|signer| (signer.pub_key.clone().into(), signer.weight))
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    Operators {
        weights_by_addresses: operators,
        threshold: worker_set.threshold,
    }
}

pub fn transfer_operatorship_params(worker_set: &WorkerSet) -> Result<HexBinary, ContractError> {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|s| (s.pub_key.clone().into(), s.weight))
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    let (addresses, weights): (Vec<Vec<u8>>, Vec<_>) = operators
        .into_iter()
        .map(|(pub_key, weight)| (pub_key.to_vec(), u256_to_u128(weight)))
        .unzip();

    Ok(to_bytes(&(addresses, weights, u256_to_u128(worker_set.threshold)))?.into())
}

#[allow(dead_code)]
fn encode_proof(
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let mut operators = make_operators_with_sigs(signers);
    operators.sort(); // gateway requires operators to be sorted

    let (addresses, weights, signatures): (Vec<_>, Vec<_>, Vec<_>) = operators
        .iter()
        .map(|op| {
            (
                op.address.to_vec(),
                u256_to_u128(op.weight),
                op.signature.as_ref().map(|sig| sig.as_ref().to_vec()),
            )
        })
        .multiunzip();

    let signatures: Vec<Vec<u8>> = signatures.into_iter().flatten().collect();
    let quorum = u256_to_u128(quorum);
    Ok(to_bytes(&(addresses, weights, quorum, signatures))?.into())
}

fn make_operators_with_sigs(signers_with_sigs: Vec<(Signer, Option<Signature>)>) -> Vec<Operator> {
    signers_with_sigs
        .into_iter()
        .map(|(signer, sig)| Operator {
            address: signer.pub_key.into(),
            weight: signer.weight,
            signature: sig,
        })
        .collect()
}

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
) -> Result<HexBinary, ContractError> {
    if payload_hash.len() != 32 {
        return Err(ContractError::InvalidMessage {
            reason: format!("payload hash is not 32 bytes {}", payload_hash.to_hex()),
        });
    }

    let destination_address = <[u8; 32]>::try_from(
        HexBinary::from_hex(&destination_address)?.to_vec(),
    )
    .map_err(|_| ContractError::InvalidMessage {
        reason: format!(
            "destination_address is not a valid Sui address: {}",
            destination_address
        ),
    })?;

    Ok(to_bytes(&(
        source_chain,
        source_address,
        destination_address,
        payload_hash.to_vec(),
    ))
    .expect("couldn't serialize command as bcs")
    .into())
}

fn make_command_id(command_id: &HexBinary) -> [u8; 32] {
    // command-ids are fixed length sequences
    command_id
        .to_vec()
        .try_into()
        .expect("couldn't convert command id to 32 byte array")
}

pub fn encode(data: &Data) -> HexBinary {
    // destination chain id must be u64 for sui
    let destination_chain_id = u256_to_u64(data.destination_chain_id);

    let (commands_ids, command_types, command_params): (Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>) =
        data.commands
            .iter()
            .map(|command| {
                (
                    make_command_id(&command.id),
                    command.ty.to_string(),
                    command.params.to_vec(),
                )
            })
            .multiunzip();

    to_bytes(&(
        destination_chain_id,
        commands_ids,
        command_types,
        command_params,
    ))
    .expect("couldn't encode batch as bcs")
    .into()
}

pub fn msg_digest(command_batch: &CommandBatch) -> HexBinary {
    // Sui is just mimicking EVM here
    let unsigned = [
        "\x19Sui Signed Message:\n".as_bytes(), // Keccek256 hash length = 32
        encode(&command_batch.data).as_slice(),
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
                        identity,
                    )
                    .map(Signature::EcdsaRecoverable)
                    .ok();
            }

            (signer, signature)
        })
        .collect::<Vec<_>>();
    let input = to_bytes(&(
        encode(&command_batch.data).to_vec(),
        encode_proof(quorum, signers)?.to_vec(),
    ))?;
    Ok(input.into())
}

fn u256_to_u128(val: Uint256) -> u128 {
    val.to_string().parse().expect("value is larger than u128")
}

fn u256_to_u64(chain_id: Uint256) -> u64 {
    chain_id
        .to_string()
        .parse()
        .expect("value is larger than u64")
}

#[cfg(test)]
mod test {

    use std::vec;

    use axelar_wasm_std::operators::Operators;
    use bcs::from_bytes;
    use connection_router::state::{CrossChainId, Message};
    use cosmwasm_std::{Addr, HexBinary, Uint256};

    use multisig::{
        key::{PublicKey, Signature},
        msg::Signer,
    };

    use crate::{
        encoding::{
            bcs::{
                command_params, encode, encode_execute_data, encode_proof, make_command_id,
                make_operators, transfer_operatorship_params, u256_to_u128, u256_to_u64,
            },
            CommandBatchBuilder, Data,
        },
        test::test_data,
        types::{BatchID, Command, CommandBatch},
    };

    use super::msg_digest;
    #[test]
    fn test_transfer_operatorship_params() {
        let worker_set = test_data::new_worker_set();

        let res = transfer_operatorship_params(&worker_set);
        assert!(res.is_ok());

        let decoded = from_bytes(&res.unwrap());
        assert!(decoded.is_ok());

        let (operators, weights, quorum): (Vec<Vec<u8>>, Vec<u128>, u128) = decoded.unwrap();

        let mut expected: Vec<(Vec<u8>, u128)> = worker_set
            .signers
            .into_iter()
            .map(|s| (s.pub_key.as_ref().to_vec(), u256_to_u128(s.weight)))
            .collect();
        expected.sort_by_key(|op| op.0.clone());
        let (operators_expected, weights_expected): (Vec<Vec<u8>>, Vec<u128>) =
            expected.into_iter().unzip();

        assert_eq!(operators, operators_expected);
        assert_eq!(weights, weights_expected);
        assert_eq!(quorum, u256_to_u128(worker_set.threshold));
    }

    #[test]
    fn test_make_operators() {
        let worker_set = test_data::new_worker_set();
        let mut expected: Vec<(HexBinary, _)> = worker_set
            .clone()
            .signers
            .into_iter()
            .map(|s| (s.pub_key.into(), s.weight))
            .collect();
        expected.sort_by_key(|op| op.0.clone());

        let operators = make_operators(worker_set.clone());
        let expected_operators = Operators {
            weights_by_addresses: expected,
            threshold: worker_set.threshold,
        };
        assert_eq!(operators, expected_operators);
    }

    #[test]
    fn test_u256_to_u128() {
        let val = u128::MAX;
        assert_eq!(val, u256_to_u128(Uint256::from(val)));
    }

    #[test]
    fn test_chain_id_as_u64() {
        let chain_id = 1u64;
        assert_eq!(chain_id, u256_to_u64(Uint256::from(chain_id as u128)));
    }

    #[test]
    #[should_panic]
    fn test_u256_to_u128_fails() {
        let _ = u256_to_u128(Uint256::MAX);
    }

    #[test]
    fn test_encode_proof() {
        let signers = vec![
        (Signer {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                )
                .unwrap(),
            ),
        },
        Some(Signature::EcdsaRecoverable(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap().try_into().unwrap()))),
            (Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        },
        Some(Signature::EcdsaRecoverable(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap().try_into().unwrap())))];

        let quorum = Uint256::from(10u128);
        let proof = encode_proof(quorum, signers.clone());

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        let decoded_proof: Result<(Vec<Vec<u8>>, Vec<u128>, u128, Vec<Vec<u8>>), _> =
            from_bytes(&proof);
        assert!(decoded_proof.is_ok());
        let (operators, weights, quorum_decoded, signatures): (
            Vec<Vec<u8>>,
            Vec<u128>,
            u128,
            Vec<Vec<u8>>,
        ) = decoded_proof.unwrap();

        assert_eq!(operators.len(), signers.len());
        assert_eq!(weights.len(), signers.len());
        assert_eq!(signatures.len(), signers.len());
        assert_eq!(quorum_decoded, 10u128);

        for i in 0..signers.len() {
            assert_eq!(
                operators[i],
                HexBinary::from(signers[i].0.pub_key.clone()).to_vec()
            );
            assert_eq!(weights[i], 10u128);
            assert_eq!(
                signatures[i],
                HexBinary::from(signers[i].1.clone().unwrap().as_ref()).to_vec()
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_chain_id_as_u64_fails() {
        let chain_id = u128::MAX;
        u256_to_u64(Uint256::from(chain_id));
    }

    #[test]
    fn test_make_command_id() {
        assert_eq!([0; 32], make_command_id(&HexBinary::from(vec![0; 32])));
    }

    #[test]
    #[should_panic]
    fn test_make_command_id_fails_too_large() {
        make_command_id(&HexBinary::from(vec![0; 30]));
    }

    #[test]
    fn test_command_params() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".repeat(32).into(),
            HexBinary::from_hex(&"02".repeat(32)).unwrap(),
        );
        assert!(res.is_ok());

        let res = res.unwrap();
        let params = from_bytes(&res.to_vec());
        assert!(params.is_ok());
        let (source_chain, source_address, destination_address, payload_hash): (
            String,
            String,
            [u8; 32],
            Vec<u8>,
        ) = params.unwrap();
        assert_eq!(source_chain, "Ethereum".to_string());

        assert_eq!(source_address, "00".to_string());

        assert_eq!(
            destination_address.to_vec(),
            HexBinary::from_hex(&"01".repeat(32)).unwrap().to_vec()
        );

        assert_eq!(payload_hash, vec![2; 32]);
    }

    #[test]
    fn test_invalid_destination_address() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".into(),
            HexBinary::from_hex("02").unwrap(),
        );
        assert!(!res.is_ok());
    }

    #[test]
    fn test_encode() {
        let source_chain = "Ethereum";
        let source_address = "AA";
        let destination_address = "BB".repeat(32);
        let payload_hash = HexBinary::from_hex(&"CC".repeat(32)).unwrap();
        let destination_chain_id = 1u64;
        let command_id = HexBinary::from_hex(&"FF".repeat(32)).unwrap();
        let data = Data {
            destination_chain_id: destination_chain_id.into(),
            commands: vec![Command {
                id: command_id.clone(),
                ty: crate::types::CommandType::ApproveContractCall,
                params: command_params(
                    source_chain.into(),
                    source_address.into(),
                    destination_address.clone().into(),
                    payload_hash.clone().into(),
                )
                .unwrap(),
            }],
        };
        let encoded = encode(&data);
        let decoded: Result<(u64, Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>), _> =
            from_bytes(&encoded.to_vec());
        assert!(decoded.is_ok());
        let (chain_id, command_ids, command_types, params) = decoded.unwrap();

        assert_eq!(chain_id, destination_chain_id);

        assert_eq!(command_ids.len(), 1);
        assert_eq!(command_ids[0].to_vec(), command_id.to_vec());

        assert_eq!(command_types.len(), 1);
        assert_eq!(
            command_types[0],
            crate::types::CommandType::ApproveContractCall.to_string()
        );

        assert_eq!(params.len(), 1);
        let command = from_bytes(&params[0]);
        assert!(command.is_ok());
        let (
            source_chain_decoded,
            source_address_decoded,
            destination_address_decoded,
            payload_hash_decoded,
        ): (String, String, [u8; 32], Vec<u8>) = command.unwrap();

        assert_eq!(source_chain_decoded, source_chain);

        assert_eq!(source_address_decoded, source_address);

        assert_eq!(
            destination_address_decoded.to_vec(),
            HexBinary::from_hex(&destination_address).unwrap().to_vec()
        );

        assert_eq!(payload_hash_decoded, payload_hash.to_vec());
    }

    #[test]
    fn test_msg_to_sign() {
        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Bcs);
        let _ = builder
            .add_message(Message {
                cc_id: "ethereum:foobar:1".parse().unwrap(),
                destination_address: "0F".repeat(32).parse().unwrap(),
                destination_chain: "sui".parse().unwrap(),
                source_address: "0x00".parse().unwrap(),
                payload_hash: HexBinary::from(vec![1; 32]),
            })
            .unwrap();
        let batch = builder.build().unwrap();
        let msg = msg_digest(&batch);
        assert_eq!(msg.len(), 32);

        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Bcs);
        let _ = builder
            .add_message(Message {
                cc_id: "ethereum:foobar:2".parse().unwrap(),
                destination_address: "0A".repeat(32).parse().unwrap(),
                destination_chain: "sui".parse().unwrap(),
                source_address: "0x00".parse().unwrap(),
                payload_hash: HexBinary::from(vec![2; 32]),
            })
            .unwrap();

        let batch = builder.build().unwrap();
        let msg2 = msg_digest(&batch);
        assert_ne!(msg, msg2);
    }

    #[test]
    fn test_encode_execute_data() {
        let approval = HexBinary::from_hex("8a02010000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020213617070726f7665436f6e747261637443616c6c13617070726f7665436f6e747261637443616c6c0249034554480330783000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000004c064158454c415203307831000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000087010121037286a4f1177bea06c8e15cf6ec3df0b7747a01ac2329ca2999dfd74eff59902801640000000000000000000000000000000a0000000000000000000000000000000141ef5ce016a4beed7e11761e5831805e962fca3d8901696a61a6ffd3af2b646bdc3740f64643bdb164b8151d1424eb4943d03f71e71816c00726e2d68ee55600c600").unwrap();

        let zero_addr = "00".repeat(32);

        let data = Data {
            destination_chain_id: 1u32.into(),
            commands: vec![
                Command {
                    id: HexBinary::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    ty: crate::types::CommandType::ApproveContractCall,
                    params: command_params(
                        "ETH".into(),
                        "0x0".into(),
                        zero_addr.clone(),
                        HexBinary::from([0; 32]),
                    )
                    .unwrap(),
                },
                Command {
                    id: HexBinary::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    )
                    .unwrap(),
                    ty: crate::types::CommandType::ApproveContractCall,
                    params: command_params(
                        "AXELAR".into(),
                        "0x1".into(),
                        zero_addr,
                        HexBinary::from([0; 32]),
                    )
                    .unwrap(),
                },
            ],
        };

        let command_batch = CommandBatch {
            message_ids: vec![],
            id: BatchID::new(&vec!["foobar".to_string()], None),
            data,
            encoder: crate::encoding::Encoder::Bcs,
        };
        let quorum = 10u128;

        let signer = Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint256::from(100u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "037286a4f1177bea06c8e15cf6ec3df0b7747a01ac2329ca2999dfd74eff599028",
                )
                .unwrap(),
            ),
        };
        let signature = Signature::Ecdsa(
        HexBinary::from_hex("ef5ce016a4beed7e11761e5831805e962fca3d8901696a61a6ffd3af2b646bdc3740f64643bdb164b8151d1424eb4943d03f71e71816c00726e2d68ee55600c6").unwrap().try_into().unwrap());
        let encoded = encode_execute_data(
            &command_batch,
            Uint256::from(quorum),
            vec![(signer, Some(signature))],
        );
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded.len(), approval.to_vec().len());
        assert_eq!(encoded.to_vec(), approval.to_vec());
    }
}
