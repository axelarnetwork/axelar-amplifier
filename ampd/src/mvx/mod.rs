use axelar_wasm_std::hash::Hash;
use cosmwasm_std::Uint256;
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};

use crate::mvx::error::Error;

pub mod error;
pub mod proxy;
pub mod verifier;

pub struct WeightedSigner {
    pub signer: [u8; 32],
    pub weight: Vec<u8>,
}

pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Vec<u8>,
    pub nonce: [u8; 32],
}

impl WeightedSigners {
    pub fn hash(&self) -> Hash {
        let mut encoded = Vec::new();

        for signer in self.signers.iter() {
            encoded.push(signer.signer.as_slice());
            encoded.push(signer.weight.as_slice());
        }

        encoded.push(self.threshold.as_slice());
        encoded.push(self.nonce.as_slice());

        Keccak256::digest(encoded.concat()).into()
    }
}

impl From<&Signer> for WeightedSigner {
    fn from(signer: &Signer) -> Self {
        WeightedSigner {
            signer: ed25519_key(&signer.pub_key).expect("not ed25519 key"),
            weight: uint256_to_compact_vec(signer.weight.into()),
        }
    }
}

impl From<&VerifierSet> for WeightedSigners {
    fn from(verifier_set: &VerifierSet) -> Self {
        let mut signers = verifier_set
            .signers
            .values()
            .map(WeightedSigner::from)
            .collect::<Vec<_>>();

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        WeightedSigners {
            signers,
            threshold: uint256_to_compact_vec(verifier_set.threshold.into()),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
        }
    }
}

fn uint256_to_compact_vec(value: Uint256) -> Vec<u8> {
    if value.is_zero() {
        return Vec::new();
    }

    let bytes = value.to_be_bytes();
    let slice_from = bytes.iter().position(|byte| *byte != 0).unwrap_or(0);

    bytes[slice_from..].to_vec()
}

pub fn ed25519_key(pub_key: &PublicKey) -> Result<[u8; 32], Error> {
    return match pub_key {
        PublicKey::Ed25519(ed25519_key) => Ok(<[u8; 32]>::try_from(ed25519_key.as_ref())
            .expect("couldn't convert pubkey to ed25519 public key")),
        _ => Err(Error::NotEd25519Key),
    };
}
