use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap};

use axelar_wasm_std::{Threshold, nonempty};
use axelar_wasm_std::Participant;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256, Addr, Fraction};
use multisig::key::KeyType;
use service_registry::state::Worker;
use sha2::Digest;
use multisig::key::PublicKey;
use sha3::Keccak256;

use crate::querier::Querier;
use crate::error::ContractError;

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct AxelarSigner {
    pub address: Addr,
    pub weight: u16,
    pub pub_key: PublicKey,
}

impl Into<Participant> for AxelarSigner {
    fn into(self) -> Participant {
        let weight = nonempty::Uint256::try_from(Uint256::from(self.weight as u128)).unwrap();
        Participant {
            address: self.address,
            weight,
        }
    }
}

#[cw_serde]
pub struct WorkerSet {
    pub signers: BTreeSet<AxelarSigner>,
    pub quorum: u32,
    // for hash uniqueness. The same exact worker set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
}

impl Into<multisig::worker_set::WorkerSet> for WorkerSet {
    fn into(self) -> multisig::worker_set::WorkerSet {
        let participants = self.signers.into_iter()
            .map(|s| (s.clone().into(), s.pub_key))
            .collect();
        multisig::worker_set::WorkerSet::new(
            participants,
            Uint256::from(self.quorum as u128),
            self.created_at
        )
    }
}

/*
fn convert_u32_to_nonempty_uint256(value: u32) -> nonempty::Uint256 {
    nonempty::Uint256::try_from(Uint256::from(value as u128)).unwrap()
}

impl Into<Snapshot> for WorkerSet {
    fn into(self) -> Snapshot {
        Snapshot {
            quorum: convert_u32_to_nonempty_uint256(self.quorum),
            participants: self.signers
                .into_iter()
                .map(|signer| (signer.address.to_string(), signer.into()))
                .collect(),
        }
    }
}
*/

impl WorkerSet {
    /*pub fn new(
        participants: Vec<(Participant, PublicKey)>,
        threshold: u32,
        block_height: u64,
    ) -> Self {
        let signers = participants
            .into_iter()
            .map(|(participant, pub_key)| Signer {
                address: participant.address.clone(),
                weight: participant.weight.into(),
                pub_key,
            })
            .collect();

        WorkerSet {
            signers,
            threshold,
            created_at: block_height,
        }
    }*/

    pub fn pub_keys_by_address(&self) -> HashMap<String, (KeyType, HexBinary), RandomState> {
        self
            .signers
            .clone()
            .into_iter()
            .map(|signer| {
                (
                    signer.address.to_string(),
                    (KeyType::Ecdsa, signer.pub_key.as_ref().into()),
                )
            })
            .collect()
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

fn convert_uint256_to_u16_unsafely(value: Uint256) -> u16 {
    let bytes = value.to_le_bytes();
    (bytes[0] as u16) | (bytes[1] as u16) << 8
}

// Converts a Vec<Uint256> to Vec<u16>, scaling down with precision loss, if necessary.
// We make sure that XRPL multisig and Axelar multisig both use the same scaled down numbers and have the same precision loss
fn convert_or_scale_weights(weights: Vec<Uint256>) -> Vec<u16> {
    let max_weight: Option<&Uint256> = weights.iter().max();
    match max_weight {
        Some(max_weight) => {
            let max_u16_as_uint256 = Uint256::from(u16::MAX);
            // Scaling down
            weights
                .clone()
                .into_iter()
                .map(|weight| {
                    // multiply_ratio returns a rounded down value
                    let scaled = weight.multiply_ratio(max_u16_as_uint256, *max_weight);
                    convert_uint256_to_u16_unsafely(scaled)
                })
                .collect()
        },
        None => vec![],
    }
}

pub fn get_active_worker_set(
    querier: Querier,
    signing_threshold: Threshold,
    block_height: u64,
) -> Result<WorkerSet, ContractError> {
    let workers: Vec<Worker> = querier.get_active_workers()?;

    let participants: Vec<Participant> = workers
        .into_iter()
        .map(|worker| Participant::try_from(worker))
        .filter(|result| result.is_ok())
        .map(|result| result.unwrap())
        .collect();

    let weights = convert_or_scale_weights(participants
        .clone()
        .into_iter()
        .map(|participant| Uint256::from(participant.weight))
        .collect());

    let mut signers: Vec<AxelarSigner> = vec![];
    for (i, participant) in participants.iter().enumerate() {
        let pub_key: PublicKey = querier.get_public_key(participant.address.clone().to_string())?;
        signers.push(AxelarSigner {
            address: participant.address.clone(),
            weight: weights[i],
            pub_key,
        });
    }

    let sum_of_weights: u16 = weights.iter().sum();

    let quorum = (sum_of_weights as u64)
        .checked_mul(signing_threshold.numerator().into())
        .unwrap()
        .checked_div(signing_threshold.denominator().into())
        .unwrap() as u32;

    let worker_set = WorkerSet {
        signers: signers.into_iter().collect(),
        quorum,
        created_at: block_height,
    };

    Ok(worker_set)
}

pub fn should_update_worker_set(
    new_workers: &WorkerSet,
    cur_workers: &WorkerSet,
    max_diff: usize,
) -> bool {
    new_workers.signers.difference(&cur_workers.signers).count()
        + cur_workers.signers.difference(&new_workers.signers).count()
        > max_diff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_or_scale_weights() {
        let weights = vec![Uint256::from(1u128), Uint256::from(2u128), Uint256::from(3u128)];
        let scaled_weights = convert_or_scale_weights(weights);
        assert_eq!(scaled_weights, vec![21845, 43690, 65535]);

        let weights = vec![Uint256::from(1u128), Uint256::from(2u128), Uint256::from(3u128), Uint256::from(4u128)];
        let scaled_weights = convert_or_scale_weights(weights);
        assert_eq!(scaled_weights, vec![16383, 32767, 49151, 65535]);

        let weights = vec![
            Uint256::MAX - Uint256::from(3u128),
            Uint256::MAX - Uint256::from(2u128),
            Uint256::MAX - Uint256::from(1u128),
            Uint256::MAX
        ];
        let scaled_weights = convert_or_scale_weights(weights);
        assert_eq!(scaled_weights, vec![65534, 65534, 65534, 65535]);

        let weights = vec![
            Uint256::from(0u128),
            Uint256::from(1u128),
            Uint256::MAX - Uint256::from(1u128),
            Uint256::MAX
        ];
        let scaled_weights = convert_or_scale_weights(weights);
        assert_eq!(scaled_weights, vec![0, 0, 65534, 65535]);

        let weights = vec![
            Uint256::from(100000u128),
            Uint256::from(2000000u128),
            Uint256::from(30000000u128),
            Uint256::from(400000000u128),
            Uint256::from(50000000000u128),
        ];
        let scaled_weights = convert_or_scale_weights(weights);
        assert_eq!(scaled_weights, vec![0, 2, 39, 524, 65535]);

        assert_eq!(convert_or_scale_weights(vec![] as Vec<Uint256>), vec![] as Vec<u16>);
    }
}
