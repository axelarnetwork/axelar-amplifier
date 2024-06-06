use crate::error::ContractError;
use crate::state::{
    ProverAddress, VerifierAddress, VerifierProverRecord, PROVER_PER_CHAIN,
    VERIFIER_PROVER_INDEXED_MAP,
};
use cosmwasm_std::{Addr, Deps, Order, StdResult};
use router_api::ChainName;

pub fn prover(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

fn is_verifier_in_verifier_set(deps: Deps, verifier_address: &VerifierAddress) -> StdResult<bool> {
    let verifier_entries = VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<Result<Vec<((ProverAddress, VerifierAddress), VerifierProverRecord)>, _>>();

    let verifier_present_in_sets = match verifier_entries {
        Ok(records) => records
            .iter()
            .map(|((prover_address, _), _)| prover_address)
            .any(|prover_address| !prover_address.as_str().is_empty()),
        Err(_) => false,
    };

    Ok(verifier_present_in_sets)
}

pub fn check_verifier_ready_to_unbond(
    deps: Deps,
    verifier_address: VerifierAddress,
) -> StdResult<bool> {
    if is_verifier_in_verifier_set(deps, &verifier_address)? {
        return Ok(false);
    }
    Ok(true)
}
