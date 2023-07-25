#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Order, Response,
    StdResult, Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{BondedWorkers, ExecuteMsg, InstantiateMsg, QueryMsg};
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
        ExecuteMsg::AuthorizeWorkers {
            workers,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let workers = workers
                .into_iter()
                .map(|w| deps.api.addr_validate(&w))
                .collect::<Result<Vec<Addr>, _>>()?;
            execute::authorize_worker(deps, workers, service_name)
        }
        ExecuteMsg::DeclareChainSupport {
            service_name,
            chains,
        } => execute::declare_chain_support(deps, info, service_name, chains),
        ExecuteMsg::BondWorker { service_name } => execute::bond_worker(deps, info, service_name),
        ExecuteMsg::UnbondWorker { service_name } => {
            execute::unbond_worker(deps, env, info, service_name)
        }
        ExecuteMsg::ClaimStake { service_name } => {
            execute::claim_stake(deps, env, info, service_name)
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
        workers: Vec<Addr>,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        for worker in workers {
            WORKERS.update(
                deps.storage,
                (&service_name.clone(), &worker.clone()),
                |sw| -> Result<Worker, ContractError> {
                    match sw {
                        Some(found) => {
                            if found.state != WorkerState::NotAuthorized {
                                return Err(ContractError::ServiceWorkerAlreadyAuthorized {});
                            }
                            Ok(Worker {
                                state: if found.stake >= service.min_worker_bond {
                                    WorkerState::Bonded
                                } else {
                                    WorkerState::Unbonded
                                },
                                ..found
                            })
                        }
                        None => Ok(Worker {
                            address: worker,
                            stake: Uint128::new(0),
                            state: WorkerState::Unbonded,
                            service_name: service_name.clone(),
                        }),
                    }
                },
            )?;
        }

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
                            state: if found.state != WorkerState::NotAuthorized
                                && new_stake >= service.min_worker_bond
                            {
                                WorkerState::Bonded
                            } else {
                                found.state
                            },
                            ..found
                        })
                    }
                    None => Ok(Worker {
                        address: info.sender,
                        stake: bond,
                        state: WorkerState::NotAuthorized,
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
        chains: Vec<String>,
    ) -> Result<Response, ContractError> {
        SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        WORKERS
            .may_load(deps.storage, (&service_name, &info.sender))?
            .ok_or(ContractError::WorkerNotFound {})?;

        for chain in chains {
            WORKERS_PER_CHAIN.save(deps.storage, (&service_name, &chain, &info.sender), &())?;
        }

        Ok(Response::new())
    }

    pub fn unbond_worker(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;
        let can_unbond = true; // TODO: actually query the service to determine this value

        WORKERS.update(
            deps.storage,
            (&service_name.clone(), &info.sender),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(found) => match found.state {
                        WorkerState::Bonded if can_unbond => Ok(Worker {
                            state: WorkerState::Unbonding {
                                unbonded_at: env.block.time,
                            },
                            service_name,
                            ..found
                        }),
                        WorkerState::Bonded if !can_unbond => Ok(Worker {
                            state: WorkerState::RequestedUnbonding,
                            ..found
                        }),
                        // If not enough time has passed, do nothing
                        WorkerState::Unbonding { unbonded_at: _ }
                        | WorkerState::RequestedUnbonding => {
                            Err(ContractError::InvalidWorkerState(found.state))
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
        )?;

        Ok(Response::new())
    }

    pub fn claim_stake(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        service_name: String,
    ) -> Result<Response, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        let old_stake = WORKERS
            .may_load(deps.storage, (&service_name, &info.sender))?
            .ok_or(ContractError::WorkerNotFound {})?
            .stake;

        let new_stake = WORKERS
            .update(
                deps.storage,
                (&service_name, &info.sender),
                |sw| -> Result<Worker, ContractError> {
                    match sw {
                        Some(found) => match found.state {
                            // If enough time has passed, release the stake
                            WorkerState::Unbonding { unbonded_at }
                                if unbonded_at.plus_days(service.unbonding_period_days as u64)
                                    <= env.block.time =>
                            {
                                Ok(Worker {
                                    state: WorkerState::Unbonded,
                                    stake: Uint128::zero(),
                                    ..found
                                })
                            }
                            WorkerState::Bonded
                            | WorkerState::RequestedUnbonding
                            | WorkerState::Unbonding { unbonded_at: _ } => {
                                Err(ContractError::InvalidWorkerState(found.state))
                            }
                            // For any other states, the stake can be released immediately, but the state doesn't need to change.
                            WorkerState::NotAuthorized | WorkerState::Unbonded => Ok(Worker {
                                stake: Uint128::zero(),
                                ..found
                            }),
                        },
                        None => Err(ContractError::WorkerNotFound {}),
                    }
                },
            )?
            .stake;

        assert!(old_stake == new_stake || new_stake == Uint128::zero());

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
        QueryMsg::GetBondedWorkers {
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
    ) -> StdResult<BondedWorkers> {
        let workers = WORKERS_PER_CHAIN
            .prefix((&service_name, &chain_name))
            .range(deps.storage, None, None, Order::Ascending)
            .map(|res| res.and_then(|(addr, _)| WORKERS.load(deps.storage, (&service_name, &addr))))
            .filter(|res| res.is_err() || res.as_ref().unwrap().state == WorkerState::Bonded)
            .collect::<Result<Vec<Worker>, _>>()?;

        Ok(BondedWorkers { workers })
    }
}
