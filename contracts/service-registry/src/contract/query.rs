use connection_router_api::ChainName;

use crate::state::{WeightedWorker, WORKERS, WORKERS_PER_CHAIN, WORKER_WEIGHT};

use super::*;

pub fn get_active_workers(
    deps: Deps,
    service_name: String,
    chain_name: ChainName,
) -> Result<Vec<WeightedWorker>, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    let workers: Vec<_> = WORKERS_PER_CHAIN
        .prefix((&service_name, &chain_name))
        .range(deps.storage, None, None, Order::Ascending)
        .map(|res| res.and_then(|(addr, _)| WORKERS.load(deps.storage, (&service_name, &addr))))
        .collect::<Result<Vec<Worker>, _>>()?
        .into_iter()
        .filter(|worker| match worker.bonding_state {
            BondingState::Bonded { amount } => amount >= service.min_worker_bond,
            _ => false,
        })
        .filter(|worker| worker.authorization_state == AuthorizationState::Authorized)
        .map(|worker| WeightedWorker {
            worker_info: worker,
            weight: WORKER_WEIGHT, // all workers have an identical const weight for now
        })
        .collect();

    if workers.len() < service.min_num_workers.into() {
        Err(ContractError::NotEnoughWorkers)
    } else {
        Ok(workers)
    }
}

pub fn get_worker(
    deps: Deps,
    service_name: String,
    worker: String,
) -> Result<Worker, ContractError> {
    WORKERS
        .may_load(
            deps.storage,
            (&service_name, &deps.api.addr_validate(&worker)?),
        )?
        .ok_or(ContractError::WorkerNotFound)
}

pub fn get_service(deps: Deps, service_name: String) -> Result<Service, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)
}
