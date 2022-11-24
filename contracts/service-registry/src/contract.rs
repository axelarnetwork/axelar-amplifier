#[cfg(not(feature = "library"))]
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, entry_point, to_binary};
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
    use cosmwasm_std::{BankMsg, Coin};

    use super::*;

    pub fn register_service(
        deps: DepsMut,
        service_name: String,
        chain_id: String,
        service_worker: Addr,
        num_workers: Uint128,
        min_worker_bond: Uint128,
        unbonding_period: Uint128,
        description: String,
    ) -> Result<Response, ContractError> {
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

        let bond = info
            .funds
            .iter()
            .find(|coin| coin.denom == AXL_DENOMINATION)
            .ok_or_else(|| ContractError::NotEnoughFunds { })?;

        if bond.amount < service.min_worker_bond {
            return Err(ContractError::NotEnoughFunds { });
        }

        SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &info.sender),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(_) => Err(ContractError::ServiceWorkerAlreadyRegistered {  }),
                    None => Ok(Worker {
                        bond_amount: bond.amount,
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
                                bond_amount: found.bond_amount,
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
                                bond_amount: found.bond_amount,
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

        let bonded_funds = Coin {
            denom: AXL_DENOMINATION.into(),
            amount: service_worker.bond_amount,
        };
        let res = Response::new()
            .add_message(BankMsg::Send {
                to_address: service.service_worker.into(),
                amount: vec![bonded_funds]
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
