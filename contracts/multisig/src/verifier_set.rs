use std::collections::{BTreeMap, HashMap};

use crate::{key::PublicKey, msg::Signer};
use axelar_wasm_std::Participant;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint128};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct VerifierSet {
    // An ordered map with the signer's address as the key, and the signer as the value.
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

    pub fn hash(&self) -> HexBinary {
        Keccak256::digest(serde_json::to_vec(&self).expect("couldn't serialize verifier set"))
            .as_slice()
            .into()
    }

    pub fn id(&self) -> String {
        self.hash().to_hex()
    }

    pub fn get_pub_keys(&self) -> HashMap<String, PublicKey> {
        self.signers
            .iter()
            .map(|(address, signer)| (address.clone(), signer.pub_key.clone()))
            .collect()
    }

    pub fn includes(&self, signer: &Addr) -> bool {
        self.signers.contains_key(signer.as_str())
    }
}
