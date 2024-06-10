use crate::error::ContractError;
use crate::state::{VerifierAddress, PROVER_PER_CHAIN, VERIFIER_PROVER_INDEXED_MAP};
use cosmwasm_std::{Addr, Deps, Order, StdResult};
use router_api::ChainName;

pub fn prover(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

fn is_verifier_in_any_verifier_set(deps: Deps, verifier_address: &VerifierAddress) -> bool {
    VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .any(|_| true)
}

pub fn check_verifier_ready_to_unbond(
    deps: Deps,
    verifier_address: VerifierAddress,
) -> StdResult<bool> {
    Ok(!is_verifier_in_any_verifier_set(deps, &verifier_address))
}
