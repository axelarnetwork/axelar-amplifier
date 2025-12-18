use std::collections::BTreeMap;

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::hash::Hash;
use chain_codec_api::error::Error;
use chain_codec_api::Payload;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use itertools::Itertools;
use k256::ecdsa::RecoveryId;
use multisig::key::{PublicKey, Recoverable, Signature};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use router_api::Message;
use sha3::{Digest, Keccak256};
use solana_axelar_std::hasher::Hasher;
use solana_axelar_std::pubkey::SECP256K1_COMPRESSED_PUBKEY_LEN;

// Solana offchain signature prefix (matches gateway implementation)
// This prefix is prepended to hashes before signing to prevent cross-context attacks
// Pattern: keccak256(PREFIX + unprefixed_hash)
const PREFIX: &[u8] = b"\xffsolana offchain";

#[inline]
pub fn validate_address(address: &str) -> Result<(), axelar_wasm_std::address::Error> {
    axelar_wasm_std::address::validate_address(address, &AddressFormat::Solana)
}

pub fn payload_digest(
    domain_separator: &Hash,
    _verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, Error> {
    let payload = to_payload(payload)?;
    let hash = solana_axelar_std::execute_data::hash_payload::<Hasher>(domain_separator, payload)
        .change_context(Error::InvalidPayload)?;

    // Add prefix for Solana offchain signing (matches gateway implementation)
    // Note: The verifier_set parameter is not used in Solana's payload digest calculation,
    // but it's required by the chain-codec-api interface
    let prefixed_message = [PREFIX, hash.as_slice()].concat();

    Ok(Keccak256::digest(prefixed_message).into())
}

pub fn encode_execute_data(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, Error> {
    // Convert to encoding types for transmission (UNPREFIXED data structures)
    let verifier_set_encoded = to_verifier_set(verifier_set)?;
    let payload_encoded = to_payload(payload)?;

    // Separately, compute a PREFIXED hash for signature generation only
    // This adds the prefix: keccak256(PREFIX + unprefixed_hash)
    // Gateway will add the same prefix during verification
    let prefixed_payload_hash = payload_digest(domain_separator, verifier_set, payload)?;

    // Encode the signers & their signatures
    // Note: Signatures were generated over the prefixed hash
    let mut signers_with_signatures =
        BTreeMap::<solana_axelar_std::PublicKey, solana_axelar_std::Signature>::new();
    for signer in signers {
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
    .change_context(Error::InvalidPayload)?;

    Ok(HexBinary::from(bytes))
}

/// Transform from Axelar VerifierSet to solana_axelar_std VerifierSet
fn to_verifier_set(vs: &VerifierSet) -> Result<solana_axelar_std::VerifierSet, Error> {
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

fn to_pub_key(pk: &PublicKey) -> Result<solana_axelar_std::PublicKey, Error> {
    match pk {
        PublicKey::Ecdsa(hb) => Ok(solana_axelar_std::PublicKey(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>()
                .change_context(Error::InvalidPayload)?,
        )),
        PublicKey::Ed25519(_hb) => Err(Error::InvalidPayload).change_context(Error::InvalidPayload),
    }
}

fn to_payload(payload: &Payload) -> Result<solana_axelar_std::execute_data::Payload, Error> {
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
) -> Result<solana_axelar_std::Signature, Error> {
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
                .change_context(Error::Proof)?;
            Ok(recoverable_ecdsa_to_array(&recov)?)
        }
        Signature::EcdsaRecoverable(r) => Ok(recoverable_ecdsa_to_array(r)?),
        Signature::Ed25519(_ed) => Err(Error::Proof).change_context(Error::Proof),
    }
}

fn recoverable_ecdsa_to_array(rec: &Recoverable) -> Result<solana_axelar_std::Signature, Error> {
    Ok(solana_axelar_std::Signature(
        rec.as_ref().try_into().map_err(|_| Error::Proof)?,
    ))
}
