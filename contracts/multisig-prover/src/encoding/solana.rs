// TODO: Solana encoding not yet wired up - suppress dead_code warnings
#![allow(dead_code)]

use std::array::TryFromSliceError;
use std::collections::BTreeMap;

use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use itertools::Itertools;
use k256::ecdsa::RecoveryId;
use multisig::key::{PublicKey, Recoverable, Signature};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use router_api::Message;
use sha3::{Digest, Keccak256};
use solana_axelar_std::hasher::Hasher;
use solana_axelar_std::pubkey::SECP256K1_COMPRESSED_PUBKEY_LEN;

use crate::error::ContractError;
use crate::payload::Payload;

// Solana offchain signature prefix (matches gateway implementation)
// This prefix is prepended to hashes before signing to prevent cross-context attacks
// Pattern: keccak256(PREFIX + unprefixed_hash)
const PREFIX: &[u8] = b"\xffsolana offchain";

pub fn encode_execute_data(
    signers_with_sigs: Vec<SignerWithSig>,
    verifier_set: &VerifierSet,
    payload: &Payload,
    domain_separator: &Hash,
) -> error_stack::Result<HexBinary, ContractError> {
    // Convert to encoding types for transmission (UNPREFIXED data structures)
    let verifier_set_encoded = to_verifier_set(verifier_set)?;
    let payload_encoded = to_payload(payload)?;

    // Separately, compute a PREFIXED hash for signature generation only
    // This adds the prefix: keccak256(PREFIX + unprefixed_hash)
    // Gateway will add the same prefix during verification
    let prefixed_payload_hash = payload_digest(domain_separator, payload)?;

    // Encode the signers & their signatures
    // Note: Signatures were generated over the prefixed hash
    let mut signers_with_signatures =
        BTreeMap::<solana_axelar_std::PublicKey, solana_axelar_std::Signature>::new();
    for signer in signers_with_sigs {
        let pubkey = to_pub_key(&signer.signer.pub_key)?;
        let signature = to_signature(
            &signer.signature,
            &signer.signer.pub_key,
            &prefixed_payload_hash,
        )?;
        signers_with_signatures.insert(pubkey, signature);
    }

    // Encode all the data
    // Note: This sends UNPREFIXED execute data (verifier_set_encoded, payload_encoded)
    // The gateway will add the prefix during verification to match our prefixed_payload_hash
    let bytes = solana_axelar_std::execute_data::encode(
        &verifier_set_encoded,
        &signers_with_signatures,
        *domain_separator,
        payload_encoded,
    )
    .map_err(|e| ContractError::SolanaEncoding {
        reason: e.to_string(),
    })?;

    Ok(HexBinary::from(bytes))
}

/// Computes the prefixed payload digest for signature generation.
///
/// Returns: keccak256(PREFIX + unprefixed_hash)
/// Note: This prefixed hash is used ONLY for signing. The unprefixed hash is transmitted.
pub fn payload_digest(
    domain_separator: &Hash,
    payload: &Payload,
) -> error_stack::Result<Hash, ContractError> {
    let payload = to_payload(payload)?;
    let hash = solana_axelar_std::execute_data::hash_payload::<Hasher>(domain_separator, payload)
        .map_err(|err| ContractError::SolanaEncoding {
        reason: err.to_string(),
    })?;

    // Add prefix for Solana offchain signing (matches gateway implementation)
    let prefixed_message = [PREFIX, hash.as_slice()].concat();

    Ok(Keccak256::digest(prefixed_message).into())
}

/// Transform from Axelar VerifierSet to axelar_solana_encoding VerifierSet
fn to_verifier_set(
    vs: &VerifierSet,
) -> error_stack::Result<solana_axelar_std::VerifierSet, ContractError> {
    let mut signers = BTreeMap::new();

    for (_cosmwasm_adr, signer) in vs.signers.iter() {
        let pub_key = to_pub_key(&signer.pub_key)?;
        let weight = signer.weight.u128();
        signers.insert(pub_key, weight);
    }

    let verifier_set = solana_axelar_std::VerifierSet {
        nonce: vs.created_at,
        signers,
        quorum: vs.threshold.u128(),
    };
    Ok(verifier_set)
}

fn to_pub_key(pk: &PublicKey) -> error_stack::Result<solana_axelar_std::PublicKey, ContractError> {
    match pk {
        PublicKey::Ecdsa(hb) => Ok(solana_axelar_std::PublicKey(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>()
                .map_err(|err| ContractError::SolanaEncoding {
                    reason: err.to_string(),
                })?,
        )),
        PublicKey::Ed25519(_hb) => Err(ContractError::InvalidPublicKey {
            reason: "Ed25519 public keys are not supported".to_string(),
        }
        .into()),
    }
}

fn to_payload(
    payload: &Payload,
) -> error_stack::Result<solana_axelar_std::execute_data::Payload, ContractError> {
    let payload = match payload {
        Payload::Messages(msgs) => {
            let messages = msgs.iter().map(to_msg).collect_vec();
            let messages = solana_axelar_std::message::Messages(messages);
            solana_axelar_std::execute_data::Payload::Messages(messages)
        }
        Payload::VerifierSet(vs) => {
            let verifier_set = to_verifier_set(vs)?;
            solana_axelar_std::execute_data::Payload::NewVerifierSet(verifier_set)
        }
    };
    Ok(payload)
}

fn to_msg(msg: &Message) -> solana_axelar_std::Message {
    let cc_id = solana_axelar_std::CrossChainId {
        chain: msg.cc_id.source_chain.to_string(),
        id: msg.cc_id.message_id.to_string(),
    };

    solana_axelar_std::Message {
        cc_id,
        source_address: msg.source_address.to_string(),
        destination_chain: msg.destination_chain.to_string(),
        destination_address: msg.destination_address.to_string(),
        payload_hash: msg.payload_hash,
    }
}

fn to_signature(
    sig: &Signature,
    pub_key: &PublicKey,
    prefixed_payload_hash: &[u8; 32],
) -> error_stack::Result<solana_axelar_std::Signature, ContractError> {
    // convert to eth recovery transform
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 {
        recovery_byte
            .to_byte()
            .checked_add(27)
            .expect("overflow when adding 27 to recovery byte")
    };

    match sig {
        Signature::Ecdsa(nonrec) => {
            let recov = nonrec
                .to_recoverable(prefixed_payload_hash, pub_key, recovery_transform)
                .map_err(|e| ContractError::SolanaEncoding {
                    reason: e.to_string(),
                })?;
            Ok(recoverable_ecdsa_to_array(&recov)?)
        }
        Signature::EcdsaRecoverable(r) => Ok(recoverable_ecdsa_to_array(r)?),
        Signature::Ed25519(_ed) => Err(ContractError::InvalidSignature {
            reason: "Ed25519 signatures are not supported".to_string(),
        }
        .into()),
    }
}

fn recoverable_ecdsa_to_array(
    rec: &Recoverable,
) -> error_stack::Result<solana_axelar_std::Signature, ContractError> {
    Ok(solana_axelar_std::Signature(
        rec.as_ref()
            .try_into()
            .map_err(|e: TryFromSliceError| ContractError::SolanaEncoding {
                reason: e.to_string(),
            })?,
    ))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType::Ecdsa;
    use multisig::key::Signature;
    use multisig::msg::{Signer, SignerWithSig};
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};
    use sha3::{Digest, Keccak256};
    use solana_axelar_std::hasher::Hasher;

    use super::{encode_execute_data, payload_digest, to_payload, PREFIX};
    use crate::payload::Payload;

    #[test]
    fn solana_messages_payload_digest() {
        let payload = Payload::Messages(vec![Message {
            cc_id: CrossChainId {
                source_chain: "evm".parse().unwrap(),
                message_id: "test".parse().unwrap(),
            },
            source_address: "0x4b20993bC481177ec7E8f571ceCaE8A9e22C02db"
                .parse()
                .unwrap(),
            destination_chain: "solana".parse().unwrap(),
            destination_address: "G7Vc8J6F4eZ3iA9LpKx2YwbM7TQh1NVR5BDFXUYmQH6E"
                .parse()
                .unwrap(),
            payload_hash: HexBinary::from_hex(
                "65ad329dc342a82bd1daedc42e183e6e2c272b8e2e3fd7c8f81d089736d0bc3c",
            )
            .unwrap()
            .to_array()
            .unwrap(),
        }]);
        let domain_separator: [u8; 32] =
            HexBinary::from_hex("2a15376c1277252b1bcce5a6ecd781bfbc2697dfd969ff58d8e2e116018b501e")
                .unwrap()
                .to_array()
                .unwrap();
        goldie::assert!(hex::encode(
            payload_digest(&domain_separator, &payload).unwrap()
        ));
    }

    #[test]
    fn solana_verifier_set_payload_digest() {
        let signers_data = vec![
            (
                "addr_1",
                "023a55792bb3695f426c7c5e680e91cdb7b1da77c40fa4e5753af5beeab9d5c3e4",
                5u128,
            ),
            (
                "addr_2",
                "02f603296b4a510c9b0bac70caec378b8d47b79f44f94280bd8f5cdc9a59512c5b",
                7u128,
            ),
        ];
        let payload = Payload::VerifierSet(gen_verifier_set(signers_data, 27, 2024));
        let domain_separator: [u8; 32] =
            HexBinary::from_hex("6773bd037510492f863cba62a0f3c55ac846883f33cae7266aff8be5eb9681e8")
                .unwrap()
                .to_array()
                .unwrap();

        goldie::assert!(hex::encode(
            payload_digest(&domain_separator, &payload).unwrap()
        ));
    }

    #[test]
    fn solana_approve_messages_execute_data() {
        let signers_data = vec![
            (
                "addr_1",
                "023a55792bb3695f426c7c5e680e91cdb7b1da77c40fa4e5753af5beeab9d5c3e4",
                8u128,
                Some("1FD785CC75E4E238A1FDA1CF78618028987F41AC263C508E7C0BF0653C87B4585FBC115858D12FC6E9FA9EFFBC5E140E2F23F4566900007397B36629E686505501"),
            ),
            (
                "addr_2",
                "02f603296b4a510c9b0bac70caec378b8d47b79f44f94280bd8f5cdc9a59512c5b",
                1u128,
                None
            ),
        ];

        let verifier_set = gen_verifier_set(
            signers_data
                .iter()
                .map(|(t1, t2, t3, _)| (*t1, *t2, *t3))
                .collect(),
            10,
            2024,
        );

        let signer_with_sig = gen_signers_with_sig(signers_data);

        let payload = Payload::Messages(vec![Message {
            cc_id: CrossChainId {
                source_chain: "evm".parse().unwrap(),
                message_id: "test".parse().unwrap(),
            },
            source_address: "0x4b20993bC481177ec7E8f571ceCaE8A9e22C02db"
                .parse()
                .unwrap(),
            destination_chain: "solana".parse().unwrap(),
            destination_address: "9Tp4XJZLQKdM82BHYfNAG6V3RWpLC7Y5mXo1UqKZFTJ3"
                .parse()
                .unwrap(),
            payload_hash: HexBinary::from_hex(
                "595c9108df17d1cc43e8268ec1516064299c1388bcc86fdd566bcdf400a0a1ed",
            )
            .unwrap()
            .to_array()
            .unwrap(),
        }]);

        let domain_separator =
            HexBinary::from_hex("2a15376c1277252b1bcce5a6ecd781bfbc2697dfd969ff58d8e2e116018b501e")
                .unwrap()
                .to_array()
                .unwrap();

        goldie::assert!(encode_execute_data(
            signer_with_sig,
            &verifier_set,
            &payload,
            &domain_separator
        )
        .unwrap()
        .to_hex());
    }

    #[test]
    fn solana_rotate_signers_execute_data() {
        let signers_data = vec![
            (
                "addr_1",
                "023a55792bb3695f426c7c5e680e91cdb7b1da77c40fa4e5753af5beeab9d5c3e4",
                2u128,
                Some("6386A3F3DEF9B727DD1A463D54CC5ADE23CDC378D8E5008BE6CF34C81205379060AF65DCC6BA22FB74CEE3337B910E8F6BB10A25A975FB63F10B8A733C35953C01"),
            ),
            (
                "addr_2",
                "02f603296b4a510c9b0bac70caec378b8d47b79f44f94280bd8f5cdc9a59512c5b",
                1u128,
                None,
            ),
        ];

        let verifier_set = gen_verifier_set(
            signers_data
                .iter()
                .map(|(t1, t2, t3, _)| (*t1, *t2, *t3))
                .collect(),
            1,
            2024,
        );

        let signer_with_sig = gen_signers_with_sig(signers_data);

        let payload = Payload::VerifierSet(gen_verifier_set(
            vec![
                (
                    "addr_1",
                    "023a55792bb3695f426c7c5e680e91cdb7b1da77c40fa4e5753af5beeab9d5c3e4",
                    9u128,
                ),
                (
                    "addr_2",
                    "02f603296b4a510c9b0bac70caec378b8d47b79f44f94280bd8f5cdc9a59512c5b",
                    1u128,
                ),
            ],
            17,
            2024,
        ));

        let domain_separator: [u8; 32] =
            HexBinary::from_hex("6773bd037510492f863cba62a0f3c55ac846883f33cae7266aff8be5eb9681e8")
                .unwrap()
                .to_array()
                .unwrap();

        goldie::assert!(encode_execute_data(
            signer_with_sig,
            &verifier_set,
            &payload,
            &domain_separator
        )
        .unwrap()
        .to_hex());
    }

    fn gen_verifier_set(
        signers_data: Vec<(&str, &str, u128)>,
        threshold: u128,
        created_at: u64,
    ) -> VerifierSet {
        VerifierSet {
            signers: signers_data
                .into_iter()
                .map(|(addr, pub_key, weight)| {
                    (
                        addr.to_string(),
                        Signer {
                            address: MockApi::default().addr_make(addr),
                            pub_key: (Ecdsa, HexBinary::from_hex(pub_key).unwrap())
                                .try_into()
                                .unwrap(),
                            weight: Uint128::from(weight),
                        },
                    )
                })
                .collect(),
            threshold: threshold.into(),
            created_at,
        }
    }

    fn gen_signers_with_sig(
        signers_data: Vec<(&str, &str, u128, Option<&str>)>,
    ) -> Vec<SignerWithSig> {
        signers_data
            .into_iter()
            .filter_map(|(addr, pub_key, weight, sig)| {
                sig.map(|signature| (addr, pub_key, weight, signature))
            })
            .map(|(addr, pub_key, weight, sig)| {
                Signer {
                    address: MockApi::default().addr_make(addr),
                    pub_key: (Ecdsa, HexBinary::from_hex(pub_key).unwrap())
                        .try_into()
                        .unwrap(),
                    weight: Uint128::from(weight),
                }
                .with_sig(Signature::try_from((Ecdsa, HexBinary::from_hex(sig).unwrap())).unwrap())
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_payload_digest_uses_prefix() {
        // 1. Setup test data
        let payload = Payload::Messages(vec![Message {
            cc_id: CrossChainId {
                source_chain: "evm".parse().unwrap(),
                message_id: "test".parse().unwrap(),
            },
            source_address: "0x4b20993bC481177ec7E8f571ceCaE8A9e22C02db"
                .parse()
                .unwrap(),
            destination_chain: "solana".parse().unwrap(),
            destination_address: "G7Vc8J6F4eZ3iA9LpKx2YwbM7TQh1NVR5BDFXUYmQH6E"
                .parse()
                .unwrap(),
            payload_hash: HexBinary::from_hex(
                "65ad329dc342a82bd1daedc42e183e6e2c272b8e2e3fd7c8f81d089736d0bc3c",
            )
            .unwrap()
            .to_array()
            .unwrap(),
        }]);

        let domain_separator: [u8; 32] =
            HexBinary::from_hex("2a15376c1277252b1bcce5a6ecd781bfbc2697dfd969ff58d8e2e116018b501e")
                .unwrap()
                .to_array()
                .unwrap();

        // 2. Get unprefixed hash directly from encoding library
        let payload_encoded = to_payload(&payload).unwrap();
        let unprefixed_hash = solana_axelar_std::execute_data::hash_payload::<Hasher>(
            &domain_separator,
            payload_encoded,
        )
        .unwrap();

        // 3. Get prefixed hash from our function
        let prefixed_hash = payload_digest(&domain_separator, &payload).unwrap();

        // 4. Manually compute expected prefixed hash
        let expected_prefixed_hash = {
            let prefixed_message = [PREFIX, unprefixed_hash.as_slice()].concat();
            Keccak256::digest(prefixed_message)
        };

        // 5. Verify they match
        assert_eq!(
            prefixed_hash.as_slice(),
            expected_prefixed_hash.as_slice(),
            "payload_digest should return keccak256(PREFIX + unprefixed_hash)"
        );

        // 6. Verify they are NOT the same (prefix actually changes the hash)
        assert_ne!(
            prefixed_hash.as_slice(),
            unprefixed_hash.as_slice(),
            "prefixed hash should be different from unprefixed hash"
        );
    }
}
