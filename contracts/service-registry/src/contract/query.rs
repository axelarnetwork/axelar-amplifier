use std::hash::{DefaultHasher, Hash, Hasher};

use axelar_wasm_std::address;
use cosmwasm_std::{Addr, Deps, Env, Order};
use error_stack::report;
use itertools::Itertools;
use report::ResultExt;
use router_api::ChainName;
use service_registry_api::error::ContractError;
use service_registry_api::*;

use crate::msg::{ServiceParamsOverride, VerifierDetails};
use crate::state::{self, VERIFIERS, VERIFIERS_PER_CHAIN, VERIFIER_WEIGHT};

pub fn active_verifiers(
    deps: Deps,
    env: Env,
    service_name: String,
    chain_name: ChainName,
) -> error_stack::Result<Vec<WeightedVerifier>, ContractError> {
    let service = state::service(deps.storage, &service_name, Some(&chain_name))?;

    let verifiers: Vec<_> = VERIFIERS_PER_CHAIN
        .prefix((service_name.clone(), chain_name.clone()))
        .keys(deps.storage, None, None, Order::Ascending)
        .filter_map_ok(|verifier_addr| {
            VERIFIERS
                .may_load(deps.storage, (&service_name, &verifier_addr))
                .ok()
                .flatten()
        })
        .filter_ok(|verifier| {
            matches!(
                verifier.bonding_state,
                BondingState::Bonded { amount } if amount >= service.min_verifier_bond
            )
        })
        .filter_ok(|verifier| verifier.authorization_state == AuthorizationState::Authorized)
        .map_ok(|verifier| WeightedVerifier {
            verifier_info: verifier,
            weight: VERIFIER_WEIGHT, // all verifiers have an identical const weight for now
        })
        .try_collect()
        .into_report()?;

    if verifiers.len() < service.min_num_verifiers.into() {
        return Err(report!(ContractError::NotEnoughVerifiers));
    }

    Ok(match service.max_num_verifiers {
        Some(max_verifiers) => select_top_verifiers(verifiers, max_verifiers, env.block.height),
        _ => verifiers,
    })
}

fn select_top_verifiers(
    mut verifiers: Vec<WeightedVerifier>,
    max_verifiers: u16,
    block_height: u64,
) -> Vec<WeightedVerifier> {
    if verifiers.len() <= max_verifiers as usize {
        return verifiers;
    }

    // Figure out the min weight that will make it into the set
    let cutoff_weight = {
        let nth = (max_verifiers as usize).saturating_sub(1);
        verifiers.select_nth_unstable_by(nth, |a, b| b.weight.cmp(&a.weight));
        verifiers[nth].weight
    };

    // these verifiers are guaranteed to be included
    let active_verifiers = verifiers
        .iter()
        .filter(|v| v.weight > cutoff_weight)
        .collect::<Vec<_>>();

    // figure out how many spots are left
    let remaining_slots = (max_verifiers as usize).saturating_sub(active_verifiers.len());

    // these verifiers are potentially included, need to select a subset of them
    let possibly_included = verifiers
        .iter()
        .filter(|v| v.weight == cutoff_weight)
        .collect::<Vec<_>>();
    let selected = select_k_random(possibly_included, remaining_slots, block_height);

    active_verifiers
        .into_iter()
        .chain(selected)
        .cloned()
        .collect()
}

// select k random verifiers from the given list
// k should be less than or equal to the length of the list
fn select_k_random(
    verifiers: Vec<&WeightedVerifier>,
    k: usize,
    seed: u64,
) -> Vec<&WeightedVerifier> {
    if k == verifiers.len() {
        return verifiers;
    }

    let mut hasher = DefaultHasher::new();
    verifiers
        .into_iter()
        .map(|v| {
            (
                v,
                hash_address_with_seed(&mut hasher, &v.verifier_info.address, seed),
            )
        })
        .collect::<Vec<_>>()
        .select_nth_unstable_by(k, |a, b| a.1.cmp(&b.1))
        .0
        .iter()
        .map(|(v, _)| *v)
        .collect::<Vec<_>>()
}

fn hash_address_with_seed(mut hasher: &mut DefaultHasher, address: &Addr, seed: u64) -> u64 {
    address.hash(&mut hasher);
    seed.hash(&mut hasher);
    hasher.finish()
}

pub fn verifier(
    deps: Deps,
    service_name: String,
    verifier: String,
) -> Result<VerifierDetails, axelar_wasm_std::error::ContractError> {
    let verifier_addr = address::validate_cosmwasm_address(deps.api, &verifier)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &verifier_addr))?
        .ok_or(ContractError::VerifierNotFound)?;

    let supported_chains = VERIFIERS_PER_CHAIN
        .idx
        .verifier_address
        .prefix((service_name, verifier_addr.clone()))
        .keys(deps.storage, None, None, Order::Ascending)
        .map_ok(|(_, chain, _)| chain)
        .try_collect()?;

    Ok(VerifierDetails {
        verifier,
        weight: VERIFIER_WEIGHT,
        supported_chains,
    })
}

pub fn service(
    deps: Deps,
    service_name: String,
    chain_name: Option<ChainName>,
) -> error_stack::Result<Service, ContractError> {
    state::service(deps.storage, &service_name, chain_name.as_ref())
}

pub fn service_params_override(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> error_stack::Result<Option<ServiceParamsOverride>, ContractError> {
    state::may_load_service_params_override(deps.storage, &service_name, &chain_name)
        .map(|o| o.map(Into::into))
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::{Addr, Uint128};
    use service_registry_api::{AuthorizationState, BondingState, Verifier};

    use super::*;

    fn create_weighted_verifier(address: &str, weight: u128) -> WeightedVerifier {
        WeightedVerifier {
            verifier_info: Verifier {
                address: Addr::unchecked(address),
                bonding_state: BondingState::Bonded {
                    amount: nonempty::Uint128::try_from(Uint128::from(100u128)).unwrap(),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: "test".to_string(),
            },
            weight: nonempty::Uint128::try_from(Uint128::from(weight)).unwrap(),
        }
    }

    #[test]
    fn select_top_verifiers_fewer_than_max() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
        ];

        let result = select_top_verifiers(verifiers.clone(), 5, 12345);

        // Should return all verifiers if we have fewer than max
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].verifier_info.address.to_string(), "addr1");
        assert_eq!(result[1].verifier_info.address.to_string(), "addr2");
    }

    #[test]
    fn select_top_verifiers_all_different_weights() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
            create_weighted_verifier("addr4", 70),
            create_weighted_verifier("addr5", 60),
        ];

        let result = select_top_verifiers(verifiers, 3, 12345);

        // Should return top 3 by weight
        assert_eq!(result.len(), 3);
        let addresses: Vec<String> = result
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();
        assert!(addresses.contains(&"addr1".to_string()));
        assert!(addresses.contains(&"addr2".to_string()));
        assert!(addresses.contains(&"addr3".to_string()));
    }

    #[test]
    fn select_top_verifiers_with_ties() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 100),
            create_weighted_verifier("addr3", 90),
            create_weighted_verifier("addr4", 90),
            create_weighted_verifier("addr5", 90),
        ];

        let result = select_top_verifiers(verifiers, 3, 12345);

        // Should return 3 verifiers total
        assert_eq!(result.len(), 3);

        // Both addr1 and addr2 should be included (weight 100)
        let addresses: Vec<String> = result
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();
        assert!(addresses.contains(&"addr1".to_string()));
        assert!(addresses.contains(&"addr2".to_string()));

        // Only one of addr3, addr4, addr5 should be included (randomly selected)
        let weight_90_count = result
            .iter()
            .filter(|v| v.weight == nonempty::Uint128::try_from(Uint128::from(90u128)).unwrap())
            .count();
        assert_eq!(weight_90_count, 1);
    }

    #[test]
    fn select_top_verifiers_deterministic_with_same_seed() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 90),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 90),
            create_weighted_verifier("addr4", 90),
        ];

        let result1 = select_top_verifiers(verifiers.clone(), 2, 12345);
        let result2 = select_top_verifiers(verifiers.clone(), 2, 12345);

        // Should be deterministic with same block height
        assert_eq!(result1.len(), result2.len());
        assert_eq!(
            result1[0].verifier_info.address.to_string(),
            result2[0].verifier_info.address.to_string()
        );
        assert_eq!(
            result1[1].verifier_info.address.to_string(),
            result2[1].verifier_info.address.to_string()
        );
    }

    #[test]
    fn select_top_verifiers_different_with_different_seed() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 90),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 90),
            create_weighted_verifier("addr4", 90),
            create_weighted_verifier("addr5", 90),
            create_weighted_verifier("addr6", 90),
            create_weighted_verifier("addr7", 90),
            create_weighted_verifier("addr8", 90),
            create_weighted_verifier("addr9", 90),
            create_weighted_verifier("addr10", 90),
        ];

        let result1 = select_top_verifiers(verifiers.clone(), 2, 12345);
        let result2 = select_top_verifiers(verifiers.clone(), 2, 54321);

        // Results should be different with different block heights
        assert_eq!(result1.len(), result2.len());
        // At least one should be different (very high probability)
        let same_selection = result1[0].verifier_info.address.to_string()
            == result2[0].verifier_info.address.to_string()
            && result1[1].verifier_info.address.to_string()
                == result2[1].verifier_info.address.to_string();
        assert!(!same_selection);
    }

    #[test]
    fn select_top_verifiers_mixed_scenario() {
        let verifiers = vec![
            create_weighted_verifier("high1", 100),
            create_weighted_verifier("high2", 100),
            create_weighted_verifier("mid1", 50),
            create_weighted_verifier("mid2", 50),
            create_weighted_verifier("mid3", 50),
            create_weighted_verifier("low1", 25),
        ];

        let result = select_top_verifiers(verifiers, 4, 12345);

        assert_eq!(result.len(), 4);

        // Both high weight verifiers should be included
        let addresses: Vec<String> = result
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();
        assert!(addresses.contains(&"high1".to_string()));
        assert!(addresses.contains(&"high2".to_string()));

        // Exactly 2 mid-weight verifiers should be included
        let mid_count = result
            .iter()
            .filter(|v| v.weight == nonempty::Uint128::try_from(Uint128::from(50u128)).unwrap())
            .count();
        assert_eq!(mid_count, 2);

        // No low weight verifiers should be included
        assert!(!addresses.contains(&"low1".to_string()));
    }

    #[test]
    fn select_top_verifiers_exact_max() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
        ];

        let result = select_top_verifiers(verifiers, 3, 12345);

        // Should return all verifiers when exactly at max
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_select_top_verifiers_all_same_weight() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 100),
            create_weighted_verifier("addr3", 100),
            create_weighted_verifier("addr4", 100),
            create_weighted_verifier("addr5", 100),
        ];

        let result = select_top_verifiers(verifiers, 3, 12345);

        // Should return exactly 3 verifiers, selected deterministically by hash
        assert_eq!(result.len(), 3);

        // All should have the same weight
        for verifier in &result {
            assert_eq!(
                verifier.weight,
                nonempty::Uint128::try_from(Uint128::from(100u128)).unwrap()
            );
        }
    }

    #[test]
    fn select_k_random_basic_functionality() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
            create_weighted_verifier("addr4", 70),
            create_weighted_verifier("addr5", 60),
        ];

        // Test selecting fewer than total
        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result = select_k_random(refs.clone(), 3, 12345);
        assert_eq!(result.len(), 3);

        // Test selecting all
        let result_all = select_k_random(refs.clone(), 5, 12345);
        assert_eq!(result_all.len(), 5);

        // Test selecting zero
        let result_zero = select_k_random(refs.clone(), 0, 12345);
        assert_eq!(result_zero.len(), 0);
    }

    #[test]
    fn select_k_random_returns_all_when_k_equals_length() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
        ];

        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result = select_k_random(refs.clone(), 3, 12345);

        assert_eq!(result.len(), 3);
        // Should return all verifiers when k equals length
        let result_addresses: std::collections::HashSet<String> = result
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();

        assert!(result_addresses.contains("addr1"));
        assert!(result_addresses.contains("addr2"));
        assert!(result_addresses.contains("addr3"));
    }

    #[test]
    fn select_k_random_deterministic_with_same_seed() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
            create_weighted_verifier("addr4", 70),
            create_weighted_verifier("addr5", 60),
        ];

        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result1 = select_k_random(refs.clone(), 3, 12345);
        let result2 = select_k_random(refs.clone(), 3, 12345);

        assert_eq!(result1.len(), result2.len());

        // Results should be identical with same seed
        let addresses1: Vec<String> = result1
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();
        let addresses2: Vec<String> = result2
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();

        assert_eq!(addresses1, addresses2);
    }

    #[test]
    fn select_k_random_different_results_with_different_seed() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
            create_weighted_verifier("addr3", 80),
            create_weighted_verifier("addr4", 70),
            create_weighted_verifier("addr5", 60),
            create_weighted_verifier("addr6", 50),
            create_weighted_verifier("addr7", 40),
            create_weighted_verifier("addr8", 30),
        ];

        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result1 = select_k_random(refs.clone(), 4, 12345);
        let result2 = select_k_random(refs.clone(), 4, 54321);

        assert_eq!(result1.len(), result2.len());

        let addresses1: std::collections::HashSet<String> = result1
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();
        let addresses2: std::collections::HashSet<String> = result2
            .iter()
            .map(|v| v.verifier_info.address.to_string())
            .collect();

        // With enough verifiers and different seeds, results should be different
        // (very high probability with 8 verifiers, selecting 4)
        assert_ne!(addresses1, addresses2);
    }

    #[test]
    fn select_k_random_handles_single_verifier() {
        let verifiers = [create_weighted_verifier("addr1", 100)];

        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result = select_k_random(refs.clone(), 1, 12345);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].verifier_info.address.to_string(), "addr1");
    }

    #[test]
    fn select_k_random_handles_empty_selection() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 90),
        ];

        let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
        let result = select_k_random(refs, 0, 12345);

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn select_k_random_distribution_appears_random() {
        let verifiers = vec![
            create_weighted_verifier("addr1", 100),
            create_weighted_verifier("addr2", 100),
            create_weighted_verifier("addr3", 100),
            create_weighted_verifier("addr4", 100),
        ];

        let mut selection_counts = std::collections::HashMap::new();

        // Run multiple selections with different seeds
        for seed in 1..=50 {
            let refs: Vec<&WeightedVerifier> = verifiers.iter().collect();
            let result = select_k_random(refs, 2, seed);

            for verifier in result {
                let addr = verifier.verifier_info.address.to_string();
                *selection_counts.entry(addr).or_insert(0) += 1;
            }
        }

        // Each verifier should be selected at least a few times
        // (with 50 runs selecting 2 out of 4, each should be selected ~25 times)
        for addr in ["addr1", "addr2", "addr3", "addr4"] {
            let count = selection_counts.get(addr).unwrap_or(&0);
            assert!(
                *count >= 10,
                "Verifier {} was selected {} times, expected at least 10",
                addr,
                count
            );
        }
    }
}
