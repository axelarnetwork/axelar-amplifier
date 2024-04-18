use crate::error::ContractError;
use crate::state::{ACTIVE_WORKERSET_FOR_PROVER, PROVERS_PER_CHAIN};
use connection_router_api::ChainName;
use cosmwasm_std::{Addr, Deps, StdResult};
use multisig::worker_set::WorkerSet;

pub fn provers(deps: Deps, chain_name: ChainName) -> Result<Vec<Addr>, ContractError> {
    PROVERS_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

// For now, we consider only one prover per chain
pub fn get_active_worker_set(deps: Deps, chain_name: ChainName) -> StdResult<Option<WorkerSet>> {
    let prover = provers(deps, chain_name).unwrap();
    let prover_address = &prover[0];

    let active_worker_set =
        ACTIVE_WORKERSET_FOR_PROVER.may_load(deps.storage, prover_address.clone())?;

    Ok(active_worker_set)
}
