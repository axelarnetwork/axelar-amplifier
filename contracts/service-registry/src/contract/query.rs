use router_api::ChainName;

use super::*;
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
        .prefix((&service_name, &chain_name))
        .range(deps.storage, None, None, Order::Ascending)
        .map(|res| res.and_then(|(addr, _)| VERIFIERS.load(deps.storage, (&service_name, &addr))))
        .collect::<Result<Vec<Verifier>, _>>()?
        .into_iter()
        .filter(|verifier| match verifier.bonding_state {
            BondingState::Bonded { amount } => amount >= service.min_verifier_bond,
            _ => false,
        })
        .filter(|verifier| verifier.authorization_state == AuthorizationState::Authorized)
        .map(|verifier| WeightedVerifier {
            verifier_info: verifier,
            weight: VERIFIER_WEIGHT, // all verifiers have an identical const weight for now
        })
        .collect();

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

pub fn service(deps: Deps, service_name: String) -> Result<Service, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)
}
