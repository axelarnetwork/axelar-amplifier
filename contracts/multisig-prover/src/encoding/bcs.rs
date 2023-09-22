use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};
use itertools::Itertools;
use multisig::{key::Signature, msg::Signer};

use crate::{error::ContractError, types::Operator};

use super::Data;

// TODO: all of the public functions in this file should be moved to a trait,
// that has an abi and bcs implementation (and possibly others)

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

    use bcs::from_bytes;
    use cosmwasm_std::{Addr, HexBinary, Uint256};
    use multisig::{
        key::{PublicKey, Signature},
        msg::Signer,
    };

    use crate::{
        encoding::{
            bcs::{
                command_params, encode, encode_proof, make_command_id, u256_to_u128, u256_to_u64,
            },
            Data,
        },
        types::Command,
    };

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
        Some(Signature::Ecdsa(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap()))),
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
        Some(Signature::Ecdsa(
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap())))];

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
                HexBinary::from(signers[i].1.clone().unwrap()).to_vec()
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
}
