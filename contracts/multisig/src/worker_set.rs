use std::collections::{BTreeMap, HashMap};

use crate::{key::PublicKey, msg::Signer, ContractError};
use axelar_wasm_std::Participant;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Addr, Uint64};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct WorkerSet {
    // An ordered map with the signer's address as the key, and the signer as the value.
    pub signers: BTreeMap<String, Signer>,
    pub threshold: Uint256,
    // for hash uniqueness. The same exact worker set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
    // TODO: add nonce to the voting verifier and to the evm gateway.
    // Without a nonce, updating to a worker set that is the exact same as a worker set in the past will be immediately confirmed.
    // https://github.com/axelarnetwork/axelar-amplifier/pull/70#discussion_r1323454223
}

impl WorkerSet {
    pub fn new(
        participants: Vec<(Participant, PublicKey)>,
        threshold: Uint256,
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

        WorkerSet {
            signers,
            threshold,
            created_at: block_height,
        }
    }

    pub fn hash(&self) -> HexBinary {
        Keccak256::digest(serde_json::to_vec(&self).expect("couldn't serialize worker set"))
            .as_slice()
            .into()
    }

    pub fn id(&self) -> String {
        self.hash().to_hex()
    }

    pub fn get_pub_keys(&self) -> HashMap<String, PublicKey>{
        let mut pub_keys = HashMap::new();
        self.signers.iter().map(|(address, signer)| {
            pub_keys.insert(address.clone(), signer.pub_key.clone());
        });
        pub_keys
    }

    pub fn get_signers_pub_key(&self, signer: &Addr, session_id: Uint64) -> Result<PublicKey, ContractError>  {
        match self.signers.get(&signer.to_string()) {
            Some(signer) => Ok(signer.pub_key),
            None => Err(ContractError::NotAParticipant {
                session_id,
                signer: signer.to_string(),
            }),
        }
    }
}
