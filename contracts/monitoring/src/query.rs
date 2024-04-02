use crate::error::ContractError;
use crate::state::PROVERS_PER_CHAIN;
use connection_router_api::ChainName;
use cosmwasm_std::{Addr, Deps};
use multisig::worker_set::WorkerSet;

pub fn chains_active_worker_sets(
    _deps: Deps,
    _chains: &[ChainName],
) -> Vec<(ChainName, WorkerSet)> {
    todo!()
}

pub fn provers(deps: Deps, chain_name: ChainName) -> Result<Vec<Addr>, ContractError> {
    PROVERS_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}
