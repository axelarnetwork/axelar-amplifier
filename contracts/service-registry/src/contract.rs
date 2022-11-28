#[cfg(not(feature = "library"))]
use cosmwasm_std::{Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, entry_point, to_binary};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ActiveWorker};
use crate::state::{SERVICES, SERVICE_WORKERS, Service, Worker, WorkerState};

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

const AXL_DENOMINATION: &str = "uaxl";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    unimplemented!()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterService{
            service_name,
            chain_id,
            service_worker,
            num_workers,
            min_worker_bond,
            unbonding_period,
            description
        } => execute::register_service(deps, service_name, chain_id, service_worker, num_workers, min_worker_bond, unbonding_period, description),
        ExecuteMsg::RegisterWorker {
            service_name,
            commission_rate
        } => execute::register_worker(deps, info, service_name, commission_rate),
        ExecuteMsg::DeregisterWorker { service_name } => execute::deregister_worker(deps, info, service_name),
        ExecuteMsg::UnbondWorker { service_name, worker_address } => execute::unbond_worker(deps, info, service_name, worker_address),
        ExecuteMsg::Delegate { service_name, worker_address, amount } => execute::delegate(),
    }
}

pub mod execute {
    use super::*;

    pub fn register_service(
        deps: DepsMut,
        service_name: String,
        chain_id: String,
        service_worker: Addr,
        num_workers: Uint128,
        min_worker_bond: Vec<Coin>,
        unbonding_period: Uint128,
        description: String,
    ) -> Result<Response, ContractError> {
        min_worker_bond.iter().find(|coin| coin.denom == AXL_DENOMINATION).ok_or_else(|| ContractError::AxlAssetMissing { })?;

        let key = &service_name.clone();

        SERVICES.update(
            deps.storage,
            key,
            |s| -> Result<Service, ContractError> {
                match s {
                    Some(_one) => Err(ContractError::ServiceAlreadyExists {  }),
                    None => Ok(Service {
                        name: service_name,
                        chain_id,
                        service_worker,
                        num_workers,
                        min_worker_bond,
                        unbonding_period,
                        description,
                    })
                }
            }
        )?;

        // Response with attributes? event?
        Ok(Response::new())
    }

    pub fn register_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
        commission_rate: Uint128
    ) -> Result<Response, ContractError> {
        let service = match SERVICES.load(deps.storage, &service_name) {
            Ok(service) => Ok(service),
            Err(_) => Err(ContractError::ServiceNotExists {  }),
        }?;

        let mut funds_iter = info
                    .funds
                    .iter();

        let is_required_bond = |fund: &&Coin, min_bond: &&Coin| -> bool {
             fund.denom == min_bond.denom && fund.amount >= min_bond.amount
        };

        let unfunded_coins: Vec<Coin> = service.min_worker_bond
            .clone()
            .iter()
            .cloned()
            .filter(|min_bond| funds_iter.find(|fund| is_required_bond(fund, &min_bond)).is_none())
            .collect();

        if !unfunded_coins.is_empty() {
            return Err(ContractError::NotEnoughFunds { assets: unfunded_coins })
        }

        if info.funds.len() != service.min_worker_bond.len() {
            return Err(ContractError::UnsupportedAssetBond { })
        }

        SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &info.sender),
            |sw| -> Result<Worker, ContractError> {
                if let Some(found) = sw {
                    if found.state == WorkerState::Inactive {
                        Ok(Worker {
                            bonded_coins: info.funds,
                            commission_rate,
                            state: WorkerState::Active
                        })
                    } else {
                        Err(ContractError::ServiceWorkerAlreadyRegistered {  })
                    }
                } else {
                    Ok(Worker {
                        bonded_coins: info.funds,
                        commission_rate,
                        state: WorkerState::Active
                    })
                }
            }
        )?;

        Ok(Response::new())
    }

    pub fn deregister_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String) -> Result<Response, ContractError> {

        SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &info.sender),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Active {
                            Ok(Worker {
                                bonded_coins: found.bonded_coins,
                                commission_rate: found.commission_rate,
                                state: WorkerState::Deregistering,
                            })
                        } else {
                            Err(ContractError::InvalidWorkerState {  })
                        }
                    },
                    None => Err(ContractError::UnregisteredWorker {  })
                }
            }
        )?;

        Ok(Response::new())
    }

    pub fn unbond_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
        worker_address: Addr
    ) -> Result<Response, ContractError> {
        let service = SERVICES.load(deps.storage, &service_name)?;

        if service.service_worker != info.sender {
            return Err(ContractError::Unauthorized {  })
        }

        let service_worker = SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &worker_address),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Deregistering {
                            Ok(Worker {
                                bonded_coins: found.bonded_coins,
                                commission_rate: found.commission_rate,
                                state: WorkerState::Inactive,
                            })
                        } else {
                            Err(ContractError::InvalidWorkerState {  })
                        }
                    },
                    None => Err(ContractError::UnregisteredWorker {  })
                }
            }
        )?;

        let res = Response::new()
            .add_message(BankMsg::Send {
                to_address: service.service_worker.into(),
                amount: service_worker.bonded_coins
            });

        Ok(res)
    }

    pub fn delegate() -> Result<Response, ContractError> {

        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkers {  } => to_binary(&query::get_active_workers()?),
    }
}

pub mod query {
    use super::*;

    pub fn get_active_workers() -> StdResult<Vec<ActiveWorker>> {
        todo!();
    }

}

#[cfg(test)]
mod tests {}
