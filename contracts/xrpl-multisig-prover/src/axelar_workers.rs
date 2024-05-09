use itertools::Itertools;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use axelar_wasm_std::Participant;
use axelar_wasm_std::{nonempty, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Fraction, HexBinary, Uint256};
use multisig::{
    key::{KeyType, PublicKey},
    msg::Signer,
};
use service_registry::state::WeightedWorker;

use crate::error::ContractError;
use crate::querier::Querier;

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct AxelarSigner {
    pub address: Addr,
    pub weight: u16,
    pub pub_key: PublicKey,
}

impl From<AxelarSigner> for Participant {
    fn from(signer: AxelarSigner) -> Self {
        let weight = nonempty::Uint256::try_from(Uint256::from(u128::from(signer.weight))).unwrap();
        Self {
            address: signer.address,
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

impl From<WorkerSet> for multisig::worker_set::WorkerSet {
    fn from(worker_set: WorkerSet) -> Self {
        let participants = worker_set
            .signers
            .into_iter()
            .map(|s| (s.clone().into(), s.pub_key))
            .collect();
        multisig::worker_set::WorkerSet::new(
            participants,
            Uint256::from(u128::from(worker_set.quorum)),
            worker_set.created_at,
        )
    }
}

impl WorkerSet {
    pub fn pub_keys_by_address(&self) -> HashMap<String, (KeyType, HexBinary), RandomState> {
        self.signers
            .iter()
            .map(|signer| {
                (
                    signer.address.to_string(),
                    (KeyType::Ecdsa, signer.pub_key.as_ref().into()),
                )
            })
            .collect()
    }
}

fn convert_uint256_to_u16(value: Uint256) -> Result<u16, ContractError> {
    if value > Uint256::from(u16::MAX) {
        return Err(ContractError::GenericError(
            "Overflow, cannot convert value to u16".to_owned(),
        ));
    }
    let bytes = value.to_le_bytes();
    Ok(u16::from(bytes[0]) | u16::from(bytes[1]).checked_shl(8).unwrap()) // this unwrap is never supposed to fail
}

// Converts a Vec<Uint256> to Vec<u16>, scaling down with precision loss, if necessary.
// We make sure that XRPL multisig and Axelar multisig both use the same scaled down numbers and have the same precision loss
fn convert_or_scale_weights(weights: &[Uint256]) -> Result<Vec<u16>, ContractError> {
    let max_weight: Option<&Uint256> = weights.iter().max();
    match max_weight {
        Some(max_weight) => {
            let max_u16_as_uint256 = Uint256::from(u16::MAX);
            let mut result = Vec::with_capacity(weights.len());
            for &weight in weights.iter() {
                let scaled = weight.multiply_ratio(max_u16_as_uint256, *max_weight);
                result.push(convert_uint256_to_u16(scaled)?);
            }

            Ok(result)
        }
        None => Ok(vec![]),
    }
}

pub fn get_active_worker_set(
    querier: &Querier,
    signing_threshold: MajorityThreshold,
    block_height: u64,
) -> Result<WorkerSet, ContractError> {
    let workers: Vec<WeightedWorker> = querier.get_active_workers()?;

    let participants: Vec<Participant> = workers
        .into_iter()
        .map(Participant::try_from)
        .filter_map(|result| result.ok())
        .collect();

    let weights = convert_or_scale_weights(
        participants
            .iter()
            .map(|participant| Uint256::from(participant.weight))
            .collect::<Vec<Uint256>>()
            .as_slice(),
    )?;

    let mut signers: Vec<AxelarSigner> = vec![];
    for (i, participant) in participants.iter().enumerate() {
        let pub_key: PublicKey = querier.get_public_key(participant.address.to_string())?;
        signers.push(AxelarSigner {
            address: participant.address.clone(),
            weight: weights[i],
            pub_key,
        });
    }

    let sum_of_weights: u32 = weights.iter().map(|w| u32::from(*w)).sum();

    let quorum = u32::try_from(
        u64::from(sum_of_weights)
            .checked_mul(signing_threshold.numerator().into())
            .unwrap()
            .checked_div(signing_threshold.denominator().into())
            .unwrap(),
    )
    .unwrap();

    let worker_set = WorkerSet {
        signers: BTreeSet::from_iter(signers),
        quorum,
        created_at: block_height,
    };

    Ok(worker_set)
}

pub fn should_update_worker_set(
    new_workers: &multisig::worker_set::WorkerSet,
    cur_workers: &multisig::worker_set::WorkerSet,
    max_diff: usize,
) -> bool {
    new_workers.threshold != cur_workers.threshold
        || signers_symetric_difference_count(&new_workers.signers, &cur_workers.signers) > max_diff
}

fn signers_symetric_difference_count(
    s1: &BTreeMap<String, Signer>,
    s2: &BTreeMap<String, Signer>,
) -> usize {
    signers_difference_count(s1, s2).saturating_add(signers_difference_count(s2, s1))
}

fn signers_difference_count(s1: &BTreeMap<String, Signer>, s2: &BTreeMap<String, Signer>) -> usize {
    s1.values().filter(|v| !s2.values().contains(v)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_or_scale_weights() {
        let weights = vec![Uint256::from(1u128), Uint256::from(1u128)];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![65535, 65535]);

        let weights = vec![
            Uint256::from(1u128),
            Uint256::from(2u128),
            Uint256::from(3u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![21845, 43690, 65535]);

        let weights = vec![
            Uint256::from(1u128),
            Uint256::from(2u128),
            Uint256::from(3u128),
            Uint256::from(4u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![16383, 32767, 49151, 65535]);

        let weights = vec![
            Uint256::MAX - Uint256::from(3u128),
            Uint256::MAX - Uint256::from(2u128),
            Uint256::MAX - Uint256::from(1u128),
            Uint256::MAX,
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![65534, 65534, 65534, 65535]);

        let weights = vec![
            Uint256::from(0u128),
            Uint256::from(1u128),
            Uint256::MAX - Uint256::from(1u128),
            Uint256::MAX,
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![0, 0, 65534, 65535]);

        let weights = vec![
            Uint256::from(100000u128),
            Uint256::from(2000000u128),
            Uint256::from(30000000u128),
            Uint256::from(400000000u128),
            Uint256::from(50000000000u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![0, 2, 39, 524, 65535]);

        let scaled_weights = convert_or_scale_weights(&vec![]).unwrap();
        assert_eq!(scaled_weights, vec![] as Vec<u16>);
    }
}
