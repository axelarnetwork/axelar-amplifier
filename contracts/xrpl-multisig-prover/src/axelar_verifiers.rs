use itertools::Itertools;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Fraction, HexBinary, Uint128};
use multisig::key::KeyType;
use multisig::msg::Signer;
use service_registry::WeightedVerifier;
use xrpl_types::types::AxelarSigner;

use crate::error::ContractError;
use crate::querier::Querier;

#[cw_serde]
pub struct VerifierSet {
    pub signers: BTreeSet<AxelarSigner>,
    pub quorum: u32,
    // for hash uniqueness. The same exact verifier set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
}

impl From<VerifierSet> for multisig::verifier_set::VerifierSet {
    fn from(verifier_set: VerifierSet) -> Self {
        let participants = verifier_set
            .signers
            .into_iter()
            .map(|s| (s.clone().into(), s.pub_key))
            .collect();
        multisig::verifier_set::VerifierSet::new(
            participants,
            Uint128::from(u128::from(verifier_set.quorum)),
            verifier_set.created_at,
        )
    }
}

impl VerifierSet {
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

fn convert_uint128_to_u16(value: Uint128) -> Result<u16, ContractError> {
    if value > Uint128::from(u16::MAX) {
        return Err(ContractError::Overflow);
    }
    let bytes = value.to_le_bytes();
    Ok(u16::from(bytes[0]) | u16::from(bytes[1]).checked_shl(8).unwrap()) // this unwrap is never supposed to fail
}

// Converts a Vec<Uint256> to Vec<u16>, scaling down with precision loss, if necessary.
// We make sure that XRPL multisig and Axelar multisig both use the same scaled down numbers and have the same precision loss
fn convert_or_scale_weights(weights: &[Uint128]) -> Result<Vec<u16>, ContractError> {
    let max_weight: Option<&Uint128> = weights.iter().max();
    match max_weight {
        Some(max_weight) => {
            let max_u16_as_uint128 = Uint128::from(u16::MAX);
            let mut result = Vec::with_capacity(weights.len());
            for &weight in weights.iter() {
                let scaled = weight.multiply_ratio(max_u16_as_uint128, *max_weight);
                result.push(convert_uint128_to_u16(scaled)?);
            }

            Ok(result)
        }
        None => Ok(vec![]),
    }
}

const MAX_NUM_XRPL_MULTISIG_SIGNERS: usize = 32;

fn mul_ceil(value: u64, numerator: u64, denominator: u64) -> u64 {
    assert!(denominator > 0, "denominator must be non-zero");

    let dividend = value * numerator;
    let floor_result = dividend / denominator;
    let remainder = dividend % denominator;

    if remainder > 0 {
        floor_result + 1
    } else {
        floor_result
    }
}

pub fn active_verifiers(
    querier: &Querier,
    signing_threshold: MajorityThreshold,
    block_height: u64,
) -> Result<VerifierSet, ContractError> {
    let verifiers: Vec<WeightedVerifier> = querier.active_verifiers()?;

    let verifiers_with_pubkeys = verifiers
        .into_iter()
        .filter_map(|verifier| {
            let address = verifier.verifier_info.address.clone();
            querier.public_key(address.to_string())
            .ok()
            .map(|pk| (verifier, pk))
        })
        .collect::<Vec<_>>();

    let num_of_verifiers = verifiers_with_pubkeys.len();
    if num_of_verifiers > MAX_NUM_XRPL_MULTISIG_SIGNERS {
        return Err(ContractError::TooManyVerifiers);
    }

    let service = querier.service()?;
    if num_of_verifiers < service.min_num_verifiers.try_into().expect("minimum number of verifiers is too large") {
        return Err(ContractError::NotEnoughVerifiers);
    }

    let weights = convert_or_scale_weights(
        verifiers_with_pubkeys
            .clone()
            .iter()
            .map(|(verifier, _)| Uint128::from(verifier.weight))
            .collect::<Vec<Uint128>>()
            .as_slice(),
    )?;

    let mut signers: Vec<AxelarSigner> = vec![];
    for (i, (verifier, pub_key)) in verifiers_with_pubkeys.iter().enumerate() {
        signers.push(AxelarSigner {
            address: verifier.verifier_info.address.clone(),
            weight: weights[i],
            pub_key: pub_key.clone(),
        });
    }

    let sum_of_weights = weights.iter().map(|w| u64::from(*w)).sum();
    let numerator = u64::from(signing_threshold.numerator());
    let denominator = u64::from(signing_threshold.denominator());
    let quorum = u32::try_from(mul_ceil(sum_of_weights, numerator, denominator)).unwrap();

    let verifier_set = VerifierSet {
        signers: BTreeSet::from_iter(signers),
        quorum,
        created_at: block_height,
    };

    Ok(verifier_set)
}

pub fn should_update_verifier_set(
    new_verifiers: &multisig::verifier_set::VerifierSet,
    cur_verifiers: &multisig::verifier_set::VerifierSet,
    max_diff: usize,
) -> bool {
    new_verifiers.threshold != cur_verifiers.threshold
        || signers_symetric_difference_count(&new_verifiers.signers, &cur_verifiers.signers) > max_diff
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
        let weights = vec![Uint128::from(1u128), Uint128::from(1u128)];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![65535, 65535]);

        let weights = vec![
            Uint128::from(1u128),
            Uint128::from(2u128),
            Uint128::from(3u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![21845, 43690, 65535]);

        let weights = vec![
            Uint128::from(1u128),
            Uint128::from(2u128),
            Uint128::from(3u128),
            Uint128::from(4u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![16383, 32767, 49151, 65535]);

        let weights = vec![
            Uint128::MAX - Uint128::from(3u128),
            Uint128::MAX - Uint128::from(2u128),
            Uint128::MAX - Uint128::from(1u128),
            Uint128::MAX,
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![65534, 65534, 65534, 65535]);

        let weights = vec![
            Uint128::from(0u128),
            Uint128::from(1u128),
            Uint128::MAX - Uint128::from(1u128),
            Uint128::MAX,
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![0, 0, 65534, 65535]);

        let weights = vec![
            Uint128::from(100000u128),
            Uint128::from(2000000u128),
            Uint128::from(30000000u128),
            Uint128::from(400000000u128),
            Uint128::from(50000000000u128),
        ];
        let scaled_weights = convert_or_scale_weights(&weights).unwrap();
        assert_eq!(scaled_weights, vec![0, 2, 39, 524, 65535]);

        let scaled_weights = convert_or_scale_weights(&vec![]).unwrap();
        assert_eq!(scaled_weights, vec![] as Vec<u16>);
    }
}
