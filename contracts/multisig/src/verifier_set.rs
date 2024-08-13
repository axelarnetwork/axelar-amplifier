use std::collections::{BTreeMap, HashMap};

use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::Participant;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint128};
use sha3::{Digest, Keccak256};

use crate::key::PublicKey;
use crate::msg::Signer;

#[cw_serde]
pub struct VerifierSet {
    // An ordered map with the signer's axelar address as the key, and the signer as the value.
    pub signers: BTreeMap<String, Signer>,
    pub threshold: Uint128,
    // for hash uniqueness. The same exact verifier set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
}

impl VerifierSet {
    pub fn new(
        participants: Vec<(Participant, PublicKey)>,
        threshold: Uint128,
        block_height: u64,
    ) -> Self {
        let signers = participants
            .into_iter()
            .map(|(participant, pub_key)| {
                (
                    participant.address.clone().to_string(),
                    Signer {
                        address: participant.address,
                        weight: participant.weight.into(),
                        pub_key,
                    },
                )
            })
            .collect();

        VerifierSet {
            signers,
            threshold,
            created_at: block_height,
        }
    }

    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();

        // Length prefix the bytes to be hashed to prevent hash collisions
        hasher.update(self.signers.len().to_be_bytes());

        self.signers.values().for_each(|signer| {
            hasher.update(signer.address.as_bytes());
            hasher.update(signer.pub_key.as_ref());
            hasher.update(signer.weight.to_be_bytes());
        });

        hasher.update(self.threshold.to_be_bytes());
        hasher.update(self.created_at.to_be_bytes());

        hasher.finalize().into()
    }

    pub fn id(&self) -> String {
        HexBinary::from(self.hash()).to_hex()
    }

    pub fn pub_keys(&self) -> HashMap<String, PublicKey> {
        self.signers
            .iter()
            .map(|(address, signer)| (address.clone(), signer.pub_key.clone()))
            .collect()
    }

    pub fn includes(&self, signer: &Addr) -> bool {
        self.signers.contains_key(signer.as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::key::KeyType;
    use crate::test::common::{build_verifier_set, ecdsa_test_data};

    // If this test fails, it means the verifier set hash has changed and therefore a migration is needed.
    #[test]
    fn verifier_set_hash_unchanged() {
        let signers = ecdsa_test_data::signers();
        let verifier_set = build_verifier_set(KeyType::Ecdsa, &signers);

        goldie::assert_json!(hex::encode(verifier_set.hash()));
    }

    // If this test fails, it means the verifier set hash has changed and therefore a migration is needed.
    #[test]
    fn verifier_set_id_unchanged() {
        let signers = ecdsa_test_data::signers();
        let verifier_set = build_verifier_set(KeyType::Ecdsa, &signers);

        goldie::assert_json!(verifier_set.id());
    }
}
