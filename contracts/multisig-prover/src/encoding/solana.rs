use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use itertools::Itertools;
use k256::ecdsa::RecoveryId;
use multisig::{
    key::{PublicKey, Recoverable, Signature},
    msg::SignerWithSig,
    verifier_set::VerifierSet,
};
use router_api::Message;
use std::{array::TryFromSliceError, collections::BTreeMap};

use crate::{error::ContractError, payload::Payload};

pub fn encode_execute_data(
    signers_with_sigs: Vec<SignerWithSig>,
    verifier_set: &VerifierSet,
    payload: &Payload,
    domain_separator: &Hash,
) -> error_stack::Result<HexBinary, ContractError> {
    // construct the base types
    let verifier_set = to_verifier_set(&verifier_set)?;
    let payload = to_payload(payload)?;
    let payload_hash =
        axelar_solana_encoding::hash_payload(domain_separator, &verifier_set, payload.clone())
            .map_err(|err| ContractError::SolanaEncoding {
                reason: err.to_string(),
            })?;

    // encode the signers & their signatures
    let mut signers_with_signatures = BTreeMap::<
        axelar_solana_encoding::types::pubkey::PublicKey,
        axelar_solana_encoding::types::pubkey::Signature,
    >::new();
    for signer in signers_with_sigs {
        let pubkey = to_pub_key(&signer.signer.pub_key)?;
        let signature = to_signature(&signer.signature, &signer.signer.pub_key, &payload_hash)?;
        signers_with_signatures.insert(pubkey, signature);
    }

    // encode all the data
    let bytes = axelar_solana_encoding::encode(
        &verifier_set,
        &signers_with_signatures,
        *domain_separator,
        payload,
    )
    .map_err(|e| ContractError::SolanaEncoding {
        reason: e.to_string(),
    })?;

    Ok(HexBinary::from(bytes))
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> error_stack::Result<Hash, ContractError> {
    let verifier_set = to_verifier_set(verifier_set)?;
    let payload = to_payload(payload)?;
    let hash = axelar_solana_encoding::hash_payload(domain_separator, &verifier_set, payload)
        .map_err(|err| ContractError::SolanaEncoding {
            reason: err.to_string(),
        })?;
    Ok(hash)
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
    use axelar_solana_encoding::types::pubkey::ED25519_PUBKEY_LEN;
    use axelar_solana_encoding::types::pubkey::SECP256K1_COMPRESSED_PUBKEY_LEN;
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
            let messages = msgs.into_iter().map(|msg| to_msg(msg)).collect_vec();
            let messages = axelar_solana_encoding::types::messages::Messages(messages);
            axelar_solana_encoding::types::payload::Payload::Messages(messages)
        }
        Payload::VerifierSet(vs) => {
            let verifier_set = to_verifier_set(&vs)?;
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
    payload_hash: &[u8; 32],
) -> error_stack::Result<axelar_solana_encoding::types::pubkey::Signature, ContractError> {
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 { recovery_byte.to_byte() };
    match sig {
        Signature::Ecdsa(nonrec) => {
            let recov = nonrec
                .to_recoverable(payload_hash, pub_key, recovery_transform)
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
