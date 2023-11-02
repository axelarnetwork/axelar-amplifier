use std::collections::BTreeSet;

use crate::key::PublicKey;
use crate::msg::Signer;
use axelar_wasm_std::Participant;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, Uint256};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct WorkerSet {
    pub signers: BTreeSet<Signer>,
    pub threshold: Uint256,
    // for hash uniqueness. The same exact worker set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
}

impl WorkerSet {
    pub fn new(
        participants: Vec<(Participant, PublicKey)>,
        threshold: Uint256,
        block_height: u64,
    ) -> Result<Self, StdError> {
        let signers = participants
            .into_iter()
            .map(|(participant, pub_key)| Signer {
                address: participant.address.clone(),
                weight: participant.weight.into(),
                pub_key,
            })
            .collect();

        Ok(WorkerSet {
            signers,
            threshold,
            created_at: block_height,
        })
    }

    pub fn hash(&self) -> HexBinary {
        Keccak256::digest(serde_json::to_vec(&self).expect("couldn't serialize worker set"))
            .as_slice()
            .into()
    }

    pub fn id(&self) -> String {
        self.hash().to_hex()
    }
}
