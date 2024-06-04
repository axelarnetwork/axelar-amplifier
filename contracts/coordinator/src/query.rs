use crate::error::ContractError;
use crate::state::{
    VerifierAddress, ACTIVE_VERIFIER_SET_FOR_PROVER,
    PROVER_PER_CHAIN, VERIFIER_PROVER_INDEXED_MAP,
};
use cosmwasm_std::{Addr, Deps, Order, StdResult};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use std::collections::HashSet;

pub fn prover(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

pub fn active_verifier_set(deps: Deps, chain_name: ChainName) -> StdResult<Option<VerifierSet>> {
    match prover(deps, chain_name) {
        Ok(prover_address) => {
            let active_worker_set =
                ACTIVE_VERIFIER_SET_FOR_PROVER.may_load(deps.storage, prover_address)?;
            Ok(active_worker_set)
        }
        Err(_err) => Ok(None),
    }
}

fn is_verifier_in_verifier_set(deps: Deps, verifier_address: &Addr) -> StdResult<bool> {
    // TODO: Use map lookup for chain names to find out which provers to query (to have better performance).
    let chain_names = PROVER_PER_CHAIN
        .keys(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;

    for chain_name in chain_names {
        if let Ok(prover_address) = PROVER_PER_CHAIN.load(deps.storage, chain_name) {
            let existing_verifiers = VERIFIER_PROVER_INDEXED_MAP
                .prefix(prover_address.clone())
                .keys(deps.storage, None, None, Order::Ascending)
                .filter_map(Result::ok)
                .collect::<HashSet<VerifierAddress>>();

            if existing_verifiers.contains(verifier_address) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> StdResult<bool> {
    if is_verifier_in_verifier_set(deps, &verifier_address)? {
        return Ok(false);
    }
    Ok(true)
}
