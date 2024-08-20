use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Order};
use router_api::ChainName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::*;
use crate::state::{WeightedVerifier, VERIFIERS, VERIFIERS_PER_CHAIN_INDEXED_MAP, VERIFIER_WEIGHT};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct VerifierDetailsResponse {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
}

pub fn active_verifiers(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> Result<Vec<WeightedVerifier>, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    let verifier_addresses: Vec<Addr> = VERIFIERS_PER_CHAIN_INDEXED_MAP
        .prefix((service_name.clone(), chain_name.clone()))
        .keys(deps.storage, None, None, Order::Ascending)
        .map(|res| res.map(|verifier| verifier))
        .collect::<Result<Vec<Addr>, _>>()?;

    let weighted_verifiers: Vec<WeightedVerifier> = verifier_addresses
        .into_iter()
        .filter_map(|verifier_addr| {
            VERIFIERS
                .may_load(deps.storage, (&service_name, &verifier_addr))
                .ok()
                .flatten()
        })
        .filter(|verifier| {
            matches!(
                verifier.bonding_state,
                BondingState::Bonded { amount } if amount >= service.min_verifier_bond
            ) && verifier.authorization_state == AuthorizationState::Authorized
        })
        .map(|verifier| WeightedVerifier {
            verifier_info: verifier,
            weight: VERIFIER_WEIGHT,
        })
        .collect();

    if weighted_verifiers.len() < service.min_num_verifiers.into() {
        Err(ContractError::NotEnoughVerifiers)
    } else {
        Ok(weighted_verifiers)
    }
}

pub fn verifier(
    deps: Deps,
    service_name: String,
    verifier: String,
) -> Result<Verifier, axelar_wasm_std::error::ContractError> {
    VERIFIERS
        .may_load(
            deps.storage,
            (
                &service_name,
                &address::validate_cosmwasm_address(deps.api, &verifier)?,
            ),
        )?
        .ok_or(ContractError::VerifierNotFound)?
        .then(Ok)
}

pub fn verifier_details(
    deps: Deps,
    service_name: String,
    verifier: String,
) -> Result<VerifierDetailsResponse, ContractError> {
    let verifier_addr = deps.api.addr_validate(&verifier)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &verifier_addr))?
        .ok_or(ContractError::VerifierNotFound)?;

    let supported_chains = VERIFIERS_PER_CHAIN_INDEXED_MAP
        .idx
        .verifier_address
        .prefix((service_name.clone(), verifier_addr.clone()))
        .keys(deps.storage, None, None, Order::Ascending)
        .map(|result| result.map(|(_, chain, _)| chain))
        .collect::<Result<Vec<ChainName>, _>>()?;

    Ok(VerifierDetailsResponse {
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
