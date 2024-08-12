use cosmwasm_std::{Addr, Deps, Order, StdResult};

use crate::state::VERIFIER_PROVER_INDEXED_MAP;

fn is_verifier_in_any_verifier_set(deps: Deps, verifier_address: &Addr) -> bool {
    VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .any(|_| true)
}

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> StdResult<bool> {
    Ok(!is_verifier_in_any_verifier_set(deps, &verifier_address))
}
