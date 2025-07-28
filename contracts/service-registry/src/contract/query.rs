use std::cmp::Ordering;

use axelar_wasm_std::address;
use cosmwasm_std::{Addr, Deps, Env, Order};
use error_stack::report;
use itertools::Itertools;
use report::ResultExt;
use router_api::ChainName;
use service_registry_api::error::ContractError;
use service_registry_api::*;
use sha3::{Digest, Keccak256};

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

    let cutoff_idx = (max_verifiers as usize).saturating_sub(1);
    // the lowest weight to be included in the set
    let cutoff_weight = verifiers
        .select_nth_unstable_by(cutoff_idx, |a, b| b.weight.cmp(&a.weight))
        .1
        .weight;

    verifiers.select_nth_unstable_by(cutoff_idx, |a, b| {
        // sort by weight, with random shuffling for verifiers with the cutoff weight
        b.weight.cmp(&a.weight).then_with(|| {
            if a.weight == cutoff_weight {
                hash_address_with_seed(&a.verifier_info.address, block_height).cmp(
                    &hash_address_with_seed(&b.verifier_info.address, block_height),
                )
            } else {
                Ordering::Equal
            }
        })
    });

    verifiers.truncate(max_verifiers as usize);
    verifiers
}

fn hash_address_with_seed(address: &Addr, seed: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(address.as_bytes());
    hasher.update(seed.to_be_bytes());
    hasher.finalize().into()
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
        use std::collections::HashMap;

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

        // Track how many times each verifier is selected
        let mut selection_counts: HashMap<String, usize> = HashMap::new();

        // Initialize counts for all verifiers
        for verifier in &verifiers {
            selection_counts.insert(verifier.verifier_info.address.to_string(), 0);
        }

        // Run selection 100 times with different seeds
        for i in 0..100 {
            let selected = select_top_verifiers(verifiers.clone(), 5, i as u64);

            // Count each selected verifier
            for verifier in selected {
                let addr = verifier.verifier_info.address.to_string();
                *selection_counts.get_mut(&addr).unwrap() += 1;
            }
        }

        // With 10 verifiers, selecting 5 each time over 100 iterations,
        // each verifier should be selected approximately 50 times (5/10 * 100)
        // Allow for some variance - each verifier should be selected between 35-65 times
        let expected = 50;
        let tolerance = 15;

        // Verify total selections equals 500 (5 verifiers * 100 iterations)
        let total_selections: usize = selection_counts.values().sum();
        assert_eq!(total_selections, 500);

        for (addr, count) in selection_counts {
            assert!(
                count >= expected - tolerance && count <= expected + tolerance,
                "Verifier {} was selected {} times, expected roughly {} (±{})",
                addr,
                count,
                expected,
                tolerance
            );
        }
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
}
