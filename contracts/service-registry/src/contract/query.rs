use cosmwasm_std::Order;
use itertools::Itertools;
use router_api::ChainName;

use super::*;
use crate::msg::VerifierDetails;
use crate::state::{WeightedVerifier, VERIFIERS, VERIFIERS_PER_CHAIN, VERIFIER_WEIGHT};

pub fn active_verifiers(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> Result<Vec<WeightedVerifier>, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

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
        .try_collect()?;

    if verifiers.len() < service.min_num_verifiers.into() {
        Err(ContractError::NotEnoughVerifiers)
    } else {
        Ok(verifiers)
    }
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

pub fn service(deps: Deps, service_name: String) -> Result<Service, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)
}
