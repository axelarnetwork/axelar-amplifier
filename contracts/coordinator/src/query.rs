use crate::error::ContractError;
use crate::state::{ACTIVE_VERIFIER_SET_FOR_PROVER, PROVER_PER_CHAIN};
use cosmwasm_std::{Addr, Deps, StdResult};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

pub fn provers(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

// For now, we consider only one prover per chain
pub fn get_active_verifier_set(
    deps: Deps,
    chain_name: ChainName,
) -> StdResult<Option<VerifierSet>> {
    let prover_address = provers(deps, chain_name).unwrap();
    let active_verifier_set =
        ACTIVE_VERIFIER_SET_FOR_PROVER.may_load(deps.storage, prover_address.clone())?;

    Ok(active_verifier_set)
}
