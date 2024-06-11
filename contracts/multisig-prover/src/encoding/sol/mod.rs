use std::{array::TryFromSliceError, collections::BTreeMap};


use itertools::Itertools;
use multisig::{key::{PublicKey, Signature}, msg::SignerWithSig, verifier_set::VerifierSet};
use router_api::Message;

use crate::{error::ContractError, payload::Payload};

const ECDSA_COMPRESSED_PUBKEY_LEN: usize = 33; // this should be probably a public constant in axelar_encoding.
const ED25519_PUBKEY_LEN: usize = 32; // this should be probably a public constant in axelar_encoding.

type Result<T> = core::result::Result<T, ContractError>;

pub fn to_worker_set(vs: &VerifierSet) -> Result<axelar_encoding::types::WorkerSet> {
    let mut signers: BTreeMap<String, axelar_encoding::types::Signer> = BTreeMap::new();

    vs.signers
        .iter()
        .try_for_each(|(address, signer)| -> Result<()> {
            let enc_signer = signer.address.to_string();
            let enc_pubkey = to_pub_key(&signer.pub_key)?;

            let enc_weight = axelar_encoding::types::U256::from_be(to_u256_be(signer.weight.u128()));

            signers.insert(
                address.clone(),
                axelar_encoding::types::Signer::new(enc_signer, enc_pubkey, enc_weight),
            );
            Ok(())
        })?;

    Ok(axelar_encoding::types::WorkerSet::new(
        vs.created_at,
        signers,
        axelar_encoding::types::U256::from_be(to_u256_be(vs.threshold.u128())),
    ))
}

fn to_pub_key(pk: &PublicKey) -> Result<axelar_encoding::types::PublicKey> {
    Ok(match pk {
        PublicKey::Ecdsa(hb) => {
            axelar_encoding::types::PublicKey::new_ecdsa(hb.to_array::<ECDSA_COMPRESSED_PUBKEY_LEN>()?)
        }
        PublicKey::Ed25519(hb) => {
            axelar_encoding::types::PublicKey::new_ed25519(hb.to_array::<ED25519_PUBKEY_LEN>()?)
        }
    })
}

// Fits a u128 into a u256 in big endian representation.
fn to_u256_be(u: u128) -> [u8; 32] {
    let mut uin256 = [0u8; 32];
    uin256[16..32].copy_from_slice(&u.to_be_bytes());
    uin256
}

impl TryFrom<&Payload> for axelar_encoding::types::Payload {
    type Error = ContractError;
    fn try_from(value: &Payload) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            Payload::Messages(msgs) => {
                axelar_encoding::types::Payload::new_messages(msgs.iter().map(to_msg).collect_vec())
            }
            Payload::VerifierSet(vs) => {
                axelar_encoding::types::Payload::new_worker_set(to_worker_set(&vs)?)
            }
        })
    }
}

fn to_msg(msg: &Message) -> axelar_encoding::types::Message {
    let enc_cc_id = axelar_encoding::types::CrossChainId::new(msg.cc_id.chain.to_string(), msg.cc_id.id.to_string());

    axelar_encoding::types::Message::new(
        enc_cc_id,
        msg.source_address.to_string(),
        msg.destination_chain.to_string(),
        msg.destination_address.to_string(),
        msg.payload_hash,
    )
}

pub fn to_weighted_signature(sig: &SignerWithSig) -> Result<axelar_encoding::types::WeightedSignature> {
    let enc_pub_key = to_pub_key(&sig.signer.pub_key)?;
    let enc_signature = to_signature(&sig.signature)?;
    let enc_weight = axelar_encoding::types::U256::from_be(to_u256_be(sig.signer.weight.u128()));

    Ok(axelar_encoding::types::WeightedSignature::new(
        enc_pub_key,
        enc_signature,
        enc_weight,
    ))
}

fn to_signature(sig: &Signature) -> Result<axelar_encoding::types::Signature> {
    match sig {
        Signature::Ecdsa(_) => unimplemented!(), // Todo: should we implement this in axelar_encoding ?

        // Following 2: We are just moving the bytes around, hoping this conversions match. Not sure if `HexBinary`
        // representation will match here with the decoding part.
        Signature::EcdsaRecoverable(r) => {
            let data = r
                .as_ref()
                .try_into()
                .map_err(|e: TryFromSliceError| ContractError::SolEncodingError(e.to_string()))?;
            Ok(axelar_encoding::types::Signature::EcdsaRecoverable(data))
        }
        Signature::Ed25519(ed) => {
            let data = ed
                .as_ref()
                .try_into()
                .map_err(|e: TryFromSliceError| ContractError::SolEncodingError(e.to_string()))?;

            Ok(axelar_encoding::types::Signature::new_ed25519(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_to_u256_be_works() {
        let integer = to_u256_be(u128::MAX);
        let expected = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
        ];
        assert_eq!(expected, integer);
    }
}
