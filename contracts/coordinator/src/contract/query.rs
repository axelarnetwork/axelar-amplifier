use crate::state::{VerifierAddress, VERIFIER_PROVER_INDEXED_MAP};
use cosmwasm_std::{Deps, Order, StdResult};

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
