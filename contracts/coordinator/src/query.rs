use crate::error::ContractError;
use crate::state::{
    ACTIVE_WORKERSET_FOR_PROVER, CHAINS_OF_WORKER, NEXT_WORKERSET_FOR_PROVER, PROVER_PER_CHAIN,
};
use cosmwasm_std::{Addr, Deps, StdResult};
use multisig::worker_set::WorkerSet;
use router_api::ChainName;

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

pub fn get_next_worker_set(deps: Deps, chain_name: ChainName) -> StdResult<Option<WorkerSet>> {
    let prover_address = provers(deps, chain_name).unwrap();
    let next_worker_set =
        NEXT_WORKERSET_FOR_PROVER.may_load(deps.storage, prover_address.clone())?;

    Ok(next_worker_set)
}

fn is_worker_in_worker_set(
    deps: Deps,
    chain_name: &ChainName,
    worker_address: &Addr,
) -> StdResult<bool> {
    if let Ok(Some(worker_set)) = get_active_worker_set(deps, chain_name.clone()) {
        if worker_set
            .signers
            .values()
            .any(|signer| signer.address == *worker_address)
        {
            return Ok(true);
        }
    }

    if let Ok(Some(worker_set)) = get_next_worker_set(deps, chain_name.clone()) {
        if worker_set
            .signers
            .values()
            .any(|signer| signer.address == *worker_address)
        {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn check_worker_ready_to_unbond(deps: Deps, worker_address: Addr) -> StdResult<bool> {
    let chains = CHAINS_OF_WORKER
        .may_load(deps.storage, worker_address.clone())?
        .unwrap_or_default();

    for chain_name in chains {
        if is_worker_in_worker_set(deps, &chain_name, &worker_address)? {
            return Ok(false);
        }
    }
    Ok(true)
}
