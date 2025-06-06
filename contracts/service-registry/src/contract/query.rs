use axelar_wasm_std::address;
use cosmwasm_std::{Deps, Order};
use error_stack::report;
use itertools::Itertools;
use report::ResultExt;
use router_api::ChainName;
use service_registry_api::error::ContractError;
use service_registry_api::*;

use crate::msg::VerifierDetails;
use crate::state::{self, VERIFIERS, VERIFIERS_PER_CHAIN, VERIFIER_WEIGHT};

pub fn active_verifiers(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> error_stack::Result<Vec<WeightedVerifier>, ContractError> {
    let service = state::service(deps.storage, &service_name, &chain_name)?;

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
        Err(report!(ContractError::NotEnoughVerifiers))
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

pub fn service(deps: Deps, service_name: String) -> error_stack::Result<Service, ContractError> {
    state::default_service_params(deps.storage, &service_name)
}

pub fn service_params(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> error_stack::Result<Service, ContractError> {
    state::service(deps.storage, &service_name, &chain_name)
}
