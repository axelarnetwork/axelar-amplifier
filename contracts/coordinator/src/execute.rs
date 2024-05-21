use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};

use multisig::worker_set::WorkerSet;
use router_api::ChainName;
use std::collections::HashSet;

use crate::error::ContractError;
use crate::state::{
    ACTIVE_WORKERSET_FOR_PROVER, CHAINS_OF_WORKER, CONFIG, NEXT_WORKERSET_FOR_PROVER,
    PROVER_PER_CHAIN,
};

pub fn check_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

pub fn register_prover(
    deps: DepsMut,
    chain_name: ChainName,
    new_prover_addr: Addr,
) -> Result<Response, ContractError> {
    PROVER_PER_CHAIN.save(deps.storage, chain_name.clone(), &(new_prover_addr))?;
    Ok(Response::new())
}

pub fn set_active_worker_set(
    deps: DepsMut,
    info: MessageInfo,
    next_worker_set: WorkerSet,
) -> Result<Response, ContractError> {
    ACTIVE_WORKERSET_FOR_PROVER.save(deps.storage, info.sender, &(next_worker_set))?;
    Ok(Response::new())
}

pub fn set_next_worker_set(
    deps: DepsMut,
    info: MessageInfo,
    next_worker_set: WorkerSet,
) -> Result<Response, ContractError> {
    NEXT_WORKERSET_FOR_PROVER.save(deps.storage, info.sender, &(next_worker_set))?;
    Ok(Response::new())
}

pub fn add_supported_chains_for_worker(
    deps: DepsMut,
    chains: Vec<ChainName>,
    worker: Addr,
) -> Result<Response, ContractError> {
    CHAINS_OF_WORKER.update(deps.storage, worker, |current_chains| {
        let mut current_chains = current_chains.unwrap_or_default();
        current_chains.extend(chains.iter().cloned());
        Ok::<HashSet<ChainName>, ContractError>(current_chains)
    })?;

    Ok(Response::new())
}
