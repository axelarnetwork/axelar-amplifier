#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Order, Response,
    StdResult, Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActiveWorkers, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{service_workers, Service, Worker, WorkerState, SERVICES};

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
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterService {
            service_name,
            service_contract,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period_days,
            description,
        } => execute::register_service(
            deps,
            service_name,
            service_contract,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period_days,
            description,
        ),
        ExecuteMsg::RegisterWorker {
            service_name,
            commission_rate,
        } => execute::register_worker(deps, info, service_name, commission_rate),
        ExecuteMsg::DeregisterWorker { service_name } => {
            execute::deregister_worker(deps, env, info, service_name)
        }
        ExecuteMsg::UnbondWorker { service_name } => {
            execute::unbond_worker(deps, env, info, service_name)
        }
        ExecuteMsg::Delegate {
            service_name: _,
            worker_address: _,
            amount: _,
        } => execute::delegate(),
    }
}

pub mod execute {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn register_service(
        deps: DepsMut,
        service_name: String,
        service_contract: Addr,
        min_num_workers: u16,
        max_num_workers: Option<u16>,
        min_worker_bond: Uint128,
        unbonding_period_days: u16,
        description: String,
    ) -> Result<Response, ContractError> {
        let key = &service_name.clone();

        SERVICES.update(deps.storage, key, |s| -> Result<Service, ContractError> {
            match s {
                Some(_one) => Err(ContractError::ServiceAlreadyExists {}),
                None => Ok(Service {
                    name: service_name,
                    service_contract,
                    min_num_workers,
                    max_num_workers,
                    min_worker_bond,
                    unbonding_period_days,
                    description,
                }),
            }
        })?;

        // Response with attributes? event?
        Ok(Response::new())
    }

    pub fn register_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
        commission_rate: Uint128,
    ) -> Result<Response, ContractError> {
        let service = match SERVICES.load(deps.storage, &service_name) {
            Ok(service) => Ok(service),
            Err(_) => Err(ContractError::ServiceNotExists {}),
        }?;

        // TODO: check max num of workers

        let bond = info
            .funds
            .iter()
            .find(|coin| coin.denom == AXL_DENOMINATION && coin.amount >= service.min_worker_bond);

        if bond.is_none() {
            return Err(ContractError::NotEnoughFunds {});
        }

        let worker_address = info.sender.clone();

        service_workers().update(
            deps.storage,
            &info.sender,
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Inactive {
                            Ok(Worker {
                                address: worker_address,
                                stake: bond.unwrap().amount,
                                commission_rate,
                                state: WorkerState::Active,
                                service_name,
                            })
                        } else {
                            Err(ContractError::ServiceWorkerAlreadyRegistered {})
                        }
                    }
                    None => Ok(Worker {
                        address: worker_address,
                        stake: bond.unwrap().amount,
                        commission_rate,
                        state: WorkerState::Active,
                        service_name,
                    }),
                }
            },
        )?;

        Ok(Response::new())
    }

    pub fn deregister_worker(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        service_workers().update(
            deps.storage,
            &info.sender,
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Active {
                            Ok(Worker {
                                state: WorkerState::Deregistering {
                                    deregistered_at: env.block.time,
                                },
                                service_name,
                                ..found
                            })
                        } else {
                            Err(ContractError::InvalidWorkerState {})
                        }
                    }
                    None => Err(ContractError::UnregisteredWorker {}),
                }
            },
        )?;

        Ok(Response::new())
    }

    pub fn unbond_worker(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES.load(deps.storage, &service_name)?;
        let worker_address = info.sender;

        let service_worker = service_workers().update(
            deps.storage,
            &worker_address,
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(Worker {
                        state: WorkerState::Deregistering { deregistered_at },
                        address,
                        stake,
                        commission_rate,
                        service_name,
                    }) => {
                        if deregistered_at.plus_days(service.unbonding_period_days as u64)
                            > env.block.time
                        {
                            return Err(ContractError::UnbondTooEarly {});
                        }
                        Ok(Worker {
                            state: WorkerState::Inactive,
                            address,
                            stake,
                            commission_rate,
                            service_name,
                        })
                    }
                    Some(_) => Err(ContractError::InvalidWorkerState {}),
                    None => Err(ContractError::UnregisteredWorker {}),
                }
            },
        )?;

        let res = Response::new().add_message(BankMsg::Send {
            to_address: worker_address.into(),
            amount: [Coin {
                denom: AXL_DENOMINATION.to_string(),
                amount: service_worker.stake,
            }]
            .to_vec(), // TODO: isolate coins
        });

        Ok(res)
    }

    pub fn delegate() -> Result<Response, ContractError> {
        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkers { service_name } => {
            to_binary(&query::get_active_workers(deps, service_name)?)
        }
    }
}

pub mod query {
    use super::*;

    pub fn get_active_workers(deps: Deps, service_name: String) -> StdResult<ActiveWorkers> {
        let result: Vec<Worker> = service_workers()
            .idx
            .service_name
            .prefix(service_name)
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| -> Option<Worker> {
                let (_, worker) = item.unwrap();
                if worker.state == WorkerState::Active {
                    Some(worker)
                } else {
                    None
                }
            })
            .collect();

        Ok(ActiveWorkers { workers: result })
    }
}

#[cfg(test)]
mod tests {}
