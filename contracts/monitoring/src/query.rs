use crate::error::ContractError;
use crate::state::{ACTIVE_WORKERSET_FOR_PROVER, PROVER_PER_CHAIN};
use connection_router_api::ChainName;
use cosmwasm_std::{Addr, Deps, StdResult};
use multisig::worker_set::WorkerSet;
use std::collections::HashSet;

pub fn provers(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

// For now, we consider only one prover per chain
pub fn get_active_worker_set(deps: Deps, chain_name: ChainName) -> StdResult<Option<WorkerSet>> {
    let prover_address = provers(deps, chain_name).unwrap();
    let active_worker_set =
        ACTIVE_WORKERSET_FOR_PROVER.may_load(deps.storage, prover_address.clone())?;

    Ok(active_worker_set)
}

pub fn check_worker_can_unbond(
    deps: Deps,
    worker_address: Addr,
    chains: HashSet<ChainName>,
) -> StdResult<bool> {
    for chain_name in chains {
        if let Ok(Some(worker_set)) = get_active_worker_set(deps, chain_name) {
            if worker_set
                .signers
                .values()
                .any(|signer| signer.address == worker_address)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
