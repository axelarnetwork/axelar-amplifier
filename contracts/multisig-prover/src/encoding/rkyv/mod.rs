use axelar_rkyv_encoding::types::{ED25519_PUBKEY_LEN, SECP256K1_COMPRESSED_PUBKEY_LEN};
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

type Result<T> = core::result::Result<T, ContractError>;

pub fn encode_execute_data(
    signers_with_sigs: Vec<SignerWithSig>,
    payload_hash: [u8; 32],
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> error_stack::Result<HexBinary, ContractError> {
    // this array contains `all` the signers, and optoinally the signatures if they exist for the given signer
    let mut signers_with_signatures = Vec::with_capacity(verifier_set.signers.len());
    for signer in verifier_set.signers.values() {
        let pubkey = to_pub_key(&signer.pub_key)?;
        let signature_found = signers_with_sigs
            .iter()
            .find(|x| x.signer.pub_key == signer.pub_key)
            .map(|x| to_weighted_signature(x, &payload_hash))
            .transpose()?
            .unwrap_or_else(|| {
                let weight = axelar_rkyv_encoding::types::U128::from(signer.weight.u128());
                (
                    pubkey,
                    axelar_rkyv_encoding::types::WeightedSigner::new(None, weight),
                )
            });

        signers_with_signatures.push(signature_found);
    }
    let created_at = verifier_set.created_at;
    let threshold = axelar_rkyv_encoding::types::U128::from(verifier_set.threshold.u128());
    let bytes = axelar_rkyv_encoding::encode::<1024>(
        // Todo reason about this "1024" magic number.
        created_at,
        threshold,
        signers_with_signatures,
        axelar_rkyv_encoding::types::Payload::try_from(payload)?,
    )
    .map_err(|e| ContractError::RkyvEncodingError(e.to_string()))?;
    Ok(HexBinary::from(bytes))
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> error_stack::Result<Hash, ContractError> {
    Ok(axelar_rkyv_encoding::hash_payload(
        &domain_separator,
        &to_verifier_set(verifier_set)?,
        &axelar_rkyv_encoding::types::Payload::try_from(payload)?,
        axelar_rkyv_encoding::hasher::generic::Keccak256Hasher::default(),
    ))
}

fn to_verifier_set(vs: &VerifierSet) -> Result<axelar_rkyv_encoding::types::VerifierSet> {
    let mut signers: BTreeMap<
        axelar_rkyv_encoding::types::PublicKey,
        axelar_rkyv_encoding::types::U128,
    > = BTreeMap::new();

    vs.signers
        .iter()
        .try_for_each(|(_, signer)| -> Result<()> {
            let enc_pubkey = to_pub_key(&signer.pub_key)?;
            let enc_weight = axelar_rkyv_encoding::types::U128::from(signer.weight.u128());

            signers.insert(enc_pubkey, enc_weight);
            Ok(())
        })?;

    Ok(axelar_rkyv_encoding::types::VerifierSet::new(
        vs.created_at,
        signers,
        axelar_rkyv_encoding::types::U128::from(vs.threshold.u128()),
    ))
}

fn to_pub_key(pk: &PublicKey) -> Result<axelar_rkyv_encoding::types::PublicKey> {
    Ok(match pk {
        PublicKey::Ecdsa(hb) => axelar_rkyv_encoding::types::PublicKey::new_ecdsa(
            hb.to_array::<SECP256K1_COMPRESSED_PUBKEY_LEN>()?,
        ),
        PublicKey::Ed25519(hb) => axelar_rkyv_encoding::types::PublicKey::new_ed25519(
            hb.to_array::<ED25519_PUBKEY_LEN>()?,
        ),
    })
}

impl TryFrom<&Payload> for axelar_rkyv_encoding::types::Payload {
    type Error = ContractError;
    fn try_from(value: &Payload) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            Payload::Messages(msgs) => axelar_rkyv_encoding::types::Payload::new_messages(
                msgs.iter().map(to_msg).collect_vec(),
            ),
            Payload::VerifierSet(vs) => {
                axelar_rkyv_encoding::types::Payload::new_verifier_set(to_verifier_set(&vs)?)
            }
        })
    }
}

fn to_msg(msg: &Message) -> axelar_rkyv_encoding::types::Message {
    let enc_cc_id = axelar_rkyv_encoding::types::CrossChainId::new(
        msg.cc_id.source_chain.to_string(),
        msg.cc_id.message_id.to_string(),
    );

    axelar_rkyv_encoding::types::Message::new(
        enc_cc_id,
        msg.source_address.to_string(),
        msg.destination_chain.to_string(),
        msg.destination_address.to_string(),
        msg.payload_hash,
    )
}

fn to_weighted_signature(
    sig: &SignerWithSig,
    payload_hash: &[u8; 32],
) -> Result<(
    axelar_rkyv_encoding::types::PublicKey,
    axelar_rkyv_encoding::types::WeightedSigner,
)> {
    let enc_pub_key = to_pub_key(&sig.signer.pub_key)?;
    let enc_signature = to_signature(&sig.signature, &sig.signer.pub_key, payload_hash)?;
    let enc_weight = axelar_rkyv_encoding::types::U128::from(sig.signer.weight.u128());

    Ok((
        enc_pub_key,
        axelar_rkyv_encoding::types::WeightedSigner::new(Some(enc_signature), enc_weight),
    ))
}

fn to_signature(
    sig: &Signature,
    pub_key: &PublicKey,
    payload_hash: &[u8; 32],
) -> Result<axelar_rkyv_encoding::types::Signature> {
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 { recovery_byte.to_byte() };
    match sig {
        Signature::Ecdsa(nonrec) => {
            let recov = nonrec
                .to_recoverable(payload_hash, pub_key, recovery_transform)
                .map_err(|e| ContractError::RkyvEncodingError(e.to_string()))?;
            Ok(axelar_rkyv_encoding::types::Signature::EcdsaRecoverable(
                recoverable_ecdsa_to_array(&recov)?,
            ))
        }
        Signature::EcdsaRecoverable(r) => {
            Ok(axelar_rkyv_encoding::types::Signature::EcdsaRecoverable(
                recoverable_ecdsa_to_array(r)?,
            ))
        }
        Signature::Ed25519(ed) => {
            let data = ed
                .as_ref()
                .try_into()
                .map_err(|e: TryFromSliceError| ContractError::RkyvEncodingError(e.to_string()))?;

            Ok(axelar_rkyv_encoding::types::Signature::new_ed25519(data))
        }
    }
}

fn recoverable_ecdsa_to_array(rec: &Recoverable) -> Result<[u8; 65]> {
    rec.as_ref()
        .try_into()
        .map_err(|e: TryFromSliceError| ContractError::RkyvEncodingError(e.to_string()))
}
