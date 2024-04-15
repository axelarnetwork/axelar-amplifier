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

pub fn get_active_worker_set(
    deps: Deps,
    prover_address: Addr,
) -> StdResult<WorkerSet> {
    ACTIVE_WORKERSET_FOR_PROVER.load(deps.storage, prover_address.clone())
}
