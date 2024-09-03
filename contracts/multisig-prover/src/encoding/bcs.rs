use std::iter;

use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use sui_gateway::{CommandType, ExecuteData, Message, MessageToSign, Proof, WeightedSigners};

use crate::encoding::{to_recoverable, Encoder};
use crate::error::ContractError;
use crate::payload::Payload;

fn encode_payload(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    let encoded: Vec<u8> = match payload {
        Payload::Messages(messages) => bcs::to_bytes(
            &messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?,
        )
        .expect("failed to serialize messages"),
        Payload::VerifierSet(verifier_set) => bcs::to_bytes(
            &WeightedSigners::try_from(verifier_set.clone())
                .change_context(ContractError::InvalidVerifierSet)?,
        )
        .expect("failed to weighted signers"),
    };

    Ok(encoded)
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let command_type = match payload {
        Payload::Messages(_) => CommandType::ApproveMessages,
        Payload::VerifierSet(_) => CommandType::RotateSigners,
    };
    let data = iter::once(command_type as u8)
        .chain(encode_payload(payload)?)
        .collect::<Vec<_>>();
    let msg = MessageToSign {
        domain_separator: (*domain_separator).into(),
        signers_hash: WeightedSigners::try_from(verifier_set.clone())
            .change_context(ContractError::InvalidVerifierSet)?
            .hash()
            .into(),
        data_hash: <[u8; 32]>::from(Keccak256::digest(data)).into(),
    };

    Ok(msg.hash())
}

/// `encode_execute_data` returns the BCS encoded execute data that contains the payload and the proof.
/// The relayer will use this data to submit the payload to the contract.
pub fn encode_execute_data(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload_digest: &Hash,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let signatures = to_recoverable(Encoder::Bcs, payload_digest, signatures);

    let encoded_payload = encode_payload(payload)?;
    let encoded_proof = bcs::to_bytes(
        &Proof::try_from((verifier_set.clone(), signatures))
            .change_context(ContractError::Proof)?,
    )
    .expect("failed to serialize proof");
    let execute_data = ExecuteData::new(encoded_payload, encoded_proof);

    Ok(bcs::to_bytes(&execute_data)
        .expect("failed to serialize execute data")
        .into())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::hash::Hash;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};

    use super::payload_digest;
    use crate::payload::Payload;

    #[test]
    fn payload_digest_should_encode_correctly_for_verifier_set() {
        let verifier_set = VerifierSet {
            signers: vec![
                (
                    "addr_1".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_1"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("02a7ecca982c2d9ac150c629699c4c601032b42429b418799d6c08ce7d966f518b").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_2".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_2"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("023e44013597b8a49df193265ae443e1a9970626d4df92e4ebad677ab2aca5c13a").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_3".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_3"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("024fa6a34ec85dc2618d730ad68ab914ccc492e54b573172083c0fa44465f54dcc").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            threshold: 2u128.into(),
            created_at: 2024,
        };
        let payload = Payload::VerifierSet(VerifierSet {
            signers: vec![
                (
                    "addr_1".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_1"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("0309613c4ae8b9ac87bdb3c4ff240a7e5f905f59754f377ccf54fbd8ce0e8ba636").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_2".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_2"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("032b14344bda89d1a0f1a976af94648f1b4a5df5397d008f3b2032267c11eda7c9").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_3".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_3"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("031fb4e7844794a28bc49e8a702c984031d8627befea844932a02e5e918f59f610").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            threshold: 2u128.into(),
            created_at: 2025,
        });

        goldie::assert!(hex::encode(
            payload_digest(&Hash::from([1; 32]), &verifier_set, &payload).unwrap()
        ));
    }

    #[test]
    fn payload_digest_should_encode_correctly_for_messages() {
        let verifier_set = VerifierSet {
            signers: vec![
                (
                    "addr_1".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_1"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("02a7ecca982c2d9ac150c629699c4c601032b42429b418799d6c08ce7d966f518b").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_2".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_2"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("023e44013597b8a49df193265ae443e1a9970626d4df92e4ebad677ab2aca5c13a").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
                (
                    "addr_3".to_string(),
                    Signer {
                        address: Addr::unchecked("addr_3"),
                        pub_key: (
                            KeyType::Ecdsa,
                            HexBinary::from_hex("024fa6a34ec85dc2618d730ad68ab914ccc492e54b573172083c0fa44465f54dcc").unwrap(),
                        )
                            .try_into()
                            .unwrap(),
                        weight: Uint128::one(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            threshold: 2u128.into(),
            created_at: 2024,
        };
        let payload = Payload::Messages(vec![
            Message {
                cc_id: CrossChainId {
                    source_chain: "ethereum".parse().unwrap(),
                    message_id:
                        "0xbb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1:0"
                            .parse()
                            .unwrap(),
                },
                source_address: "0x1a68E002efa42CF3bDEF81d66bB41f9d677420bE"
                    .parse()
                    .unwrap(),
                destination_chain: "sui".parse().unwrap(),
                destination_address:
                    "0xdf4dd40feff3c09bb5c559d0cfd7d1c5025fa802bba275453e48af7d2b437727"
                        .parse()
                        .unwrap(),
                payload_hash: [2; 32],
            },
            Message {
                cc_id: CrossChainId {
                    source_chain: "ethereum".parse().unwrap(),
                    message_id:
                        "0xd695e1ee9d73aeee677d4cec13d17351c1e86a0ce49b7fd3de94350e9cd0b3a9:1"
                            .parse()
                            .unwrap(),
                },
                source_address: "0x876EabF441B2EE5B5b0554Fd502a8E0600950cFa"
                    .parse()
                    .unwrap(),
                destination_chain: "sui".parse().unwrap(),
                destination_address:
                    "0x7bcef829e138fb8fff88671514597313153b9f5501a282bee68a2d9b66aa66e8"
                        .parse()
                        .unwrap(),
                payload_hash: [3; 32],
            },
        ]);

        goldie::assert!(hex::encode(
            payload_digest(&Hash::from([1; 32]), &verifier_set, &payload).unwrap()
        ));
    }
}
