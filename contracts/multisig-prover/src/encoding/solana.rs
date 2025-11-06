use std::array::TryFromSliceError;
use std::collections::BTreeMap;

use axelar_solana_encoding::types::pubkey::{ED25519_PUBKEY_LEN, SECP256K1_COMPRESSED_PUBKEY_LEN};
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use itertools::Itertools;
use k256::ecdsa::RecoveryId;
use multisig::key::{PublicKey, Recoverable, Signature};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use router_api::Message;
use sha3::{Digest, Keccak256};

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
    let mut signers_with_signatures = BTreeMap::<
        axelar_solana_encoding::types::pubkey::PublicKey,
        axelar_solana_encoding::types::pubkey::Signature,
    >::new();
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
    let bytes = axelar_solana_encoding::encode(
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
    let hash = axelar_solana_encoding::hash_payload(domain_separator, payload).map_err(|err| {
        ContractError::SolanaEncoding {
            reason: err.to_string(),
        }
    })?;

    // Add prefix for Solana offchain signing (matches gateway implementation)
    let prefixed_message = [PREFIX, hash.as_slice()].concat();

    Ok(Keccak256::digest(prefixed_message).into())
}

/// Transform from Axelar VerifierSet to axelar_solana_encoding VerifierSet
fn to_verifier_set(
    vs: &VerifierSet,
) -> error_stack::Result<axelar_solana_encoding::types::verifier_set::VerifierSet, ContractError> {
    let mut signers = BTreeMap::new();

    for (_cosmwasm_adr, signer) in vs.signers.iter() {
        let pub_key = to_pub_key(&signer.pub_key)?;
        let weight = signer.weight.u128();
        signers.insert(pub_key, weight);
    }

    let verifier_set = axelar_solana_encoding::types::verifier_set::VerifierSet {
        nonce: vs.created_at,
        signers,
        quorum: vs.threshold.u128(),
    };
    Ok(verifier_set)
}

fn to_pub_key(
    pk: &PublicKey,
) -> error_stack::Result<axelar_solana_encoding::types::pubkey::PublicKey, ContractError> {
    Ok(match pk {
        PublicKey::Ecdsa(hb) => axelar_solana_encoding::types::pubkey::PublicKey::Secp256k1(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>()
                .map_err(|err| ContractError::SolanaEncoding {
                    reason: err.to_string(),
                })?,
        ),
        PublicKey::Ed25519(hb) => axelar_solana_encoding::types::pubkey::PublicKey::Ed25519(
            hb.to_array::<ED25519_PUBKEY_LEN>()
                .map_err(|err| ContractError::SolanaEncoding {
                    reason: err.to_string(),
                })?,
        ),
    })
}

fn to_payload(
    payload: &Payload,
) -> error_stack::Result<axelar_solana_encoding::types::payload::Payload, ContractError> {
    let payload = match payload {
        Payload::Messages(msgs) => {
            let messages = msgs.iter().map(to_msg).collect_vec();
            let messages = axelar_solana_encoding::types::messages::Messages(messages);
            axelar_solana_encoding::types::payload::Payload::Messages(messages)
        }
        Payload::VerifierSet(vs) => {
            let verifier_set = to_verifier_set(vs)?;
            axelar_solana_encoding::types::payload::Payload::NewVerifierSet(verifier_set)
        }
    };
    Ok(payload)
}

fn to_msg(msg: &Message) -> axelar_solana_encoding::types::messages::Message {
    let cc_id = axelar_solana_encoding::types::messages::CrossChainId {
        chain: msg.cc_id.source_chain.to_string(),
        id: msg.cc_id.message_id.to_string(),
    };

    axelar_solana_encoding::types::messages::Message {
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
) -> error_stack::Result<axelar_solana_encoding::types::pubkey::Signature, ContractError> {
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 { recovery_byte.to_byte() };
    match sig {
        Signature::Ecdsa(nonrec) => {
            let recov = nonrec
                .to_recoverable(prefixed_payload_hash, pub_key, recovery_transform)
                .map_err(|e| ContractError::SolanaEncoding {
                    reason: e.to_string(),
                })?;
            Ok(
                axelar_solana_encoding::types::pubkey::Signature::EcdsaRecoverable(
                    recoverable_ecdsa_to_array(&recov)?,
                ),
            )
        }
        Signature::EcdsaRecoverable(r) => Ok(
            axelar_solana_encoding::types::pubkey::Signature::EcdsaRecoverable(
                recoverable_ecdsa_to_array(r)?,
            ),
        ),
        Signature::Ed25519(ed) => {
            let data = ed.as_ref().try_into().map_err(|e: TryFromSliceError| {
                ContractError::SolanaEncoding {
                    reason: e.to_string(),
                }
            })?;

            Ok(axelar_solana_encoding::types::pubkey::Signature::Ed25519(
                data,
            ))
        }
    }
}

fn recoverable_ecdsa_to_array(rec: &Recoverable) -> error_stack::Result<[u8; 65], ContractError> {
    let res =
        rec.as_ref()
            .try_into()
            .map_err(|e: TryFromSliceError| ContractError::SolanaEncoding {
                reason: e.to_string(),
            })?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType::Ed25519;
    use multisig::key::Signature;
    use multisig::msg::{Signer, SignerWithSig};
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};
    use sha3::{Digest, Keccak256};

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
                "5086d25f94b8c42faf7ef4325516864e179fcb2a1a9321720f0fc2b249105106",
                5u128,
            ),
            (
                "addr_2",
                "57a446f70d8243b7d5e08edcd9c5774f3f0257940df7aa84bca5b1acfc0f3ba3",
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
                "12f7d9a9463212335914b39ee90bfa2045f90b64c1f2d7b58ed335282abac4a4",
                8u128,
                Some("b5b3b0749aa585f866d802e32ca4a6356f82eb52e2a1b4797cbaa30f3d755462f2eb995c70d9099e436b8a48498e4d613ff2d3ca7618973a36c2fde17493180f"),
            ),
            (
                "addr_2",
                "4c3863e4b0252a8674c1c6ad70b3ca3002b400b49ddfae5583b21907e65c5dd8",
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
                "77dd4768dda195f8080fe970be8fec5fee9cea781718158ce19d4a331442fd57",
                2u128,
                Some("91db8ad94ab379ee9021caeb3ee852582d09d06801213256cbd2937f2ad8182f518fde7a7f8c801adde7161e05cbbb9841ac0bf3290831570a54c6ae3d089703"),
            ),
            (
                "addr_2",
                "c35aa94d2038f258ecb1bb28fbc8a83ab79d2dc0a7223fd528a8f52a14c03292",
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
                    "358a2305fc783b6072049ee6f5f76fb14c3a14d7c01e36d9ef502661bf46a011",
                    9u128,
                ),
                (
                    "addr_2",
                    "3b1caf530189a9a65ae347b18cb8bf88729ba90d2aeaf7f185b600400ab49891",
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
                            pub_key: (Ed25519, HexBinary::from_hex(pub_key).unwrap())
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
                    pub_key: (Ed25519, HexBinary::from_hex(pub_key).unwrap())
                        .try_into()
                        .unwrap(),
                    weight: Uint128::from(weight),
                }
                .with_sig(
                    Signature::try_from((Ed25519, HexBinary::from_hex(sig).unwrap())).unwrap(),
                )
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
        let unprefixed_hash =
            axelar_solana_encoding::hash_payload(&domain_separator, payload_encoded).unwrap();

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
