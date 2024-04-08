use crate::error::ContractError;
use crate::state::PROVERS_PER_CHAIN;
use connection_router_api::ChainName;
use cosmwasm_std::{to_json_binary, Addr, Deps, QueryRequest, StdResult, WasmQuery};
use multisig::worker_set::WorkerSet;
use multisig_prover::msg::QueryMsg::GetWorkerSet;
use std::collections::HashSet;

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

pub fn check_worker_is_active(
    deps: Deps,
    chain_names: HashSet<ChainName>,
    worker: Addr,
) -> StdResult<bool> {
    for chain_name in chain_names {
        if let Ok(prover_addresses) = PROVERS_PER_CHAIN.load(deps.storage, chain_name) {
            for prover_address in prover_addresses {
                let prover_active_worker_set: WorkerSet =
                    deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                        contract_addr: prover_address.to_string(),
                        msg: to_json_binary(&GetWorkerSet)?,
                    }))?;

                if prover_active_worker_set
                    .signers
                    .values()
                    .any(|signer| signer.address == worker)
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
