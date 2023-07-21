#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Order, Response,
    StdResult, Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActiveWorkers, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, Service, Worker, WorkerState, CONFIG, SERVICES};

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

pub const AXL_DENOMINATION: &str = "uaxl";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    CONFIG.save(
        deps.storage,
        &Config {
            governance: deps.api.addr_validate(&msg.governance_account)?,
        },
    )?;
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
        } => {
            execute::require_governance(&deps, info)?;
            execute::register_service(
                deps,
                service_name,
                service_contract,
                min_num_workers,
                max_num_workers,
                min_worker_bond,
                unbonding_period_days,
                description,
            )
        }
        ExecuteMsg::AuthorizeWorker {
            worker_addr,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let worker_addr = deps.api.addr_validate(&worker_addr)?;
            execute::authorize_worker(deps, worker_addr, service_name)
        }
        ExecuteMsg::DeclareChainSupport {
            service_name,
            chain_name,
        } => execute::declare_chain_support(deps, info, service_name, chain_name),
        ExecuteMsg::BondWorker { service_name } => execute::bond_worker(deps, info, service_name),
        ExecuteMsg::UnbondWorker { service_name } => {
            execute::unbond_worker(deps, env, info, service_name)
        }
    }
}

pub mod execute {
    use crate::state::{WORKERS, WORKERS_PER_CHAIN};

    use super::*;

    pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.governance != info.sender {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }

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
                None => Ok(Service {
                    name: service_name,
                    service_contract,
                    min_num_workers,
                    max_num_workers,
                    min_worker_bond,
                    unbonding_period_days,
                    description,
                }),
                _ => Err(ContractError::ServiceAlreadyExists {}),
            }
        })?;

        // Response with attributes? event?
        Ok(Response::new())
    }

    pub fn authorize_worker(
        deps: DepsMut,
        worker: Addr,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        WORKERS.update(
            deps.storage,
            (&service_name.clone(), &worker.clone()),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        if found.state != WorkerState::Pending {
                            return Err(ContractError::ServiceWorkerAlreadyAuthorized {});
                        }
                        Ok(Worker {
                            state: if found.stake >= service.min_worker_bond {
                                WorkerState::Active
                            } else {
                                WorkerState::Inactive
                            },
                            ..found
                        })
                    }
                    None => Ok(Worker {
                        address: worker,
                        stake: Uint128::new(0),
                        state: WorkerState::Inactive,
                        service_name,
                    }),
                }
            },
        )?;

        Ok(Response::new())
    }

    pub fn bond_worker(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        let bond = if !info.funds.is_empty() {
            info.funds
                .iter()
                .find(|coin| coin.denom == AXL_DENOMINATION)
                .ok_or(ContractError::WrongDenom {})?
                .amount
        } else {
            Uint128::zero() // sender can rebond currently unbonding funds by just sending no new funds
        };

        WORKERS.update(
            deps.storage,
            (&service_name.clone(), &info.sender.clone()),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => {
                        let new_stake = found.stake + bond;
                        Ok(Worker {
                            stake: new_stake,
                            state: if found.state != WorkerState::Pending
                                && new_stake >= service.min_worker_bond
                            {
                                WorkerState::Active
                            } else {
                                found.state
                            },
                            ..found
                        })
                    }
                    None => Ok(Worker {
                        address: info.sender,
                        stake: bond,
                        state: WorkerState::Pending,
                        service_name,
                    }),
                }
            },
        )?;

        Ok(Response::new())
    }

    pub fn declare_chain_support(
        deps: DepsMut,
        info: MessageInfo,
        service_name: String,
        chain_name: String,
    ) -> Result<Response, ContractError> {
        SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        WORKERS
            .may_load(deps.storage, (&service_name, &info.sender))?
            .ok_or(ContractError::WorkerNotFound {})?;

        WORKERS_PER_CHAIN.save(
            deps.storage,
            (&service_name, &chain_name, &info.sender),
            &(),
        )?;

        Ok(Response::new())
    }

    pub fn unbond_worker(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        let old_stake = WORKERS
            .load(deps.storage, (&service_name, &info.sender))?
            .stake;

        let new_stake = WORKERS
            .update(
                deps.storage,
                (&service_name.clone(), &info.sender),
                |sw| -> Result<Worker, ContractError> {
                    match sw {
                        Some(found) => match found.state {
                            WorkerState::Active => Ok(Worker {
                                state: WorkerState::Unbonding {
                                    unbonded_at: env.block.time,
                                },
                                service_name,
                                ..found
                            }),
                            // If enough time has passed, release the stake
                            WorkerState::Unbonding { unbonded_at }
                                if unbonded_at.plus_days(service.unbonding_period_days as u64)
                                    <= env.block.time =>
                            {
                                Ok(Worker {
                                    state: WorkerState::Inactive,
                                    stake: Uint128::zero(),
                                    service_name,
                                    ..found
                                })
                            }
                            // If not enough time has passed, do nothing
                            WorkerState::Unbonding { unbonded_at }
                                if unbonded_at.plus_days(service.unbonding_period_days as u64)
                                    > env.block.time =>
                            {
                                Ok(found)
                            }
                            // For any other states, the stake can be released immediately, but the state doesn't need to change.
                            _ => Ok(Worker {
                                stake: Uint128::zero(),
                                ..found
                            }),
                        },
                        None => Err(ContractError::WorkerNotFound {}),
                    }
                },
            )?
            .stake;

        if old_stake != new_stake {
            return Ok(Response::new().add_message(BankMsg::Send {
                to_address: info.sender.into(),
                amount: [Coin {
                    denom: AXL_DENOMINATION.to_string(),
                    amount: old_stake,
                }]
                .to_vec(), // TODO: isolate coins
            }));
        }

        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkers {
            service_name,
            chain_name,
        } => to_binary(&query::get_active_workers(deps, service_name, chain_name)?),
    }
}

pub mod query {
    use crate::state::{WORKERS, WORKERS_PER_CHAIN};

    use super::*;

    pub fn get_active_workers(
        deps: Deps,
        service_name: String,
        chain_name: String,
    ) -> StdResult<ActiveWorkers> {
        let workers = WORKERS_PER_CHAIN
            .prefix((&service_name, &chain_name))
            .range(deps.storage, None, None, Order::Ascending)
            .map(|res| res.and_then(|(addr, _)| WORKERS.load(deps.storage, (&service_name, &addr))))
            .filter(|res| res.is_err() || res.as_ref().unwrap().state == WorkerState::Active)
            .collect::<Result<Vec<Worker>, _>>()?;

        Ok(ActiveWorkers { workers })
    }
}
