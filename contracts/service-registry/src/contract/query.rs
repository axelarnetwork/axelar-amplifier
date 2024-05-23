use router_api::ChainName;

use crate::state::{WeightedVerifier, VERIFIERS, VERIFIERS_PER_CHAIN, VERIFIER_WEIGHT};

use super::*;

pub fn get_active_verifiers(
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

pub fn get_verifier(
    deps: Deps,
    service_name: String,
    verifier: String,
) -> Result<Verifier, ContractError> {
    VERIFIERS
        .may_load(
            deps.storage,
            (&service_name, &deps.api.addr_validate(&verifier)?),
        )?
        .ok_or(ContractError::VerifierNotFound)
}

pub fn get_service(deps: Deps, service_name: String) -> Result<Service, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)
}
