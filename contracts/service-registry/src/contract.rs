#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo,
    QueryRequest, Response, StdResult, Uint128, Uint64, WasmQuery,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActiveWorker, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Service, Worker, WorkerState, SERVICES, SERVICE_WORKERS};
use service_interface::msg::{QueryMsg as ServiceQueryMsg, UnbondAllowedResponse};

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
        ExecuteMsg::RegisterService {
            service_name,
            service_contract,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period,
            description,
        } => execute::register_service(
            deps,
            service_name,
            service_contract,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period,
            description,
        ),
        ExecuteMsg::RegisterWorker {
            service_name,
            commission_rate,
        } => execute::register_worker(deps, info, service_name, commission_rate),
        ExecuteMsg::DeregisterWorker { service_name } => {
            execute::deregister_worker(deps, info, service_name)
        }
        ExecuteMsg::UnbondWorker {
            service_name,
            worker_address,
        } => execute::unbond_worker(deps, service_name, worker_address),
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
        min_num_workers: Uint64,
        max_num_workers: Option<Uint64>,
        min_worker_bond: Vec<Coin>,
        unbonding_period: Uint128, // TODO: pending definition if we want this. Use Duration data type
        description: String,
    ) -> Result<Response, ContractError> {
        min_worker_bond
            .iter()
            .find(|coin| coin.denom == AXL_DENOMINATION)
            .ok_or(ContractError::AxlAssetMissing {})?;

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
                    unbonding_period,
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

        let mut funds_iter = info.funds.iter();

        let is_required_bond = |fund: &&Coin, min_bond: &&Coin| -> bool {
            fund.denom == min_bond.denom && fund.amount >= min_bond.amount
        };

        let unfunded_coins: Vec<Coin> = service
            .min_worker_bond
            .iter()
            .cloned()
            .filter(|min_bond| !funds_iter.any(|fund| is_required_bond(&fund, &min_bond)))
            .collect();

        if !unfunded_coins.is_empty() {
            return Err(ContractError::NotEnoughFunds {
                assets: unfunded_coins,
            });
        }

        if info.funds.len() != service.min_worker_bond.len() {
            return Err(ContractError::UnsupportedAssetBond {});
        }

        let worker_address = info.sender.clone();

        SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &info.sender),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Inactive {
                            Ok(Worker {
                                worker_address,
                                bonded_coins: info.funds,
                                commission_rate,
                                state: WorkerState::Active,
                            })
                        } else {
                            Err(ContractError::ServiceWorkerAlreadyRegistered {})
                        }
                    }
                    None => Ok(Worker {
                        worker_address,
                        bonded_coins: info.funds,
                        commission_rate,
                        state: WorkerState::Active,
                    }),
                }
            },
        )?;

        Ok(Response::new())
    }

    pub fn deregister_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &info.sender),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Active {
                            Ok(Worker {
                                worker_address: found.worker_address,
                                bonded_coins: found.bonded_coins,
                                commission_rate: found.commission_rate,
                                state: WorkerState::Deregistering,
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
        service_name: String,
        worker_address: Addr,
    ) -> Result<Response, ContractError> {
        let service = SERVICES.load(deps.storage, &service_name)?;

        let query_msg: ServiceQueryMsg = ServiceQueryMsg::UnbondAllowed {
            worker_address: worker_address.clone(),
        };
        let query_response: UnbondAllowedResponse =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service.service_contract.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        if let Some(error) = query_response.error {
            return Err(ContractError::ServiceContractError { msg: error });
        }

        let service_worker = SERVICE_WORKERS.update(
            deps.storage,
            (&service_name, &worker_address),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state == WorkerState::Deregistering {
                            Ok(Worker {
                                worker_address: found.worker_address,
                                bonded_coins: found.bonded_coins,
                                commission_rate: found.commission_rate,
                                state: WorkerState::Inactive,
                            })
                        } else {
                            Err(ContractError::InvalidWorkerState {})
                        }
                    }
                    None => Err(ContractError::UnregisteredWorker {}),
                }
            },
        )?;

        let res = Response::new().add_message(BankMsg::Send {
            to_address: service.service_contract.into(),
            amount: service_worker.bonded_coins, // TODO: isolate coins
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
        QueryMsg::GetActiveWorkers {} => to_binary(&query::get_active_workers()?),
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
