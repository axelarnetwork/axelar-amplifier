#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Order, Response,
    Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{BondedWorkers, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{BondingState, Config, Service, Worker, CONFIG, SERVICES};

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
            execute::authorize_workers(deps, workers, service_name)
        }
        ExecuteMsg::UnauthorizeWorkers {
            workers,
            service_name,
        } => {
            execute::require_governance(&deps, info)?;
            let workers = workers
                .into_iter()
                .map(|w| deps.api.addr_validate(&w))
                .collect::<Result<Vec<Addr>, _>>()?;
            execute::unauthorize_workers(deps, workers, service_name)
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
    use crate::state::{AuthorizationState, WORKERS, WORKERS_PER_CHAIN};

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

    pub fn authorize_workers(
        deps: DepsMut,
        workers: Vec<Addr>,
        service_name: String,
    ) -> Result<Response, ContractError> {
        SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        for worker in workers {
            WORKERS.update(
                deps.storage,
                (&service_name.clone(), &worker.clone()),
                |sw| -> Result<Worker, ContractError> {
                    match sw {
                        Some(worker) => Ok(Worker {
                            authorization_state: AuthorizationState::Authorized,
                            ..worker
                        }),
                        None => Ok(Worker {
                            address: worker,
                            bonding_state: BondingState::Unbonded,
                            authorization_state: AuthorizationState::Authorized,
                            service_name: service_name.clone(),
                        }),
                    }
                },
            )?;
        }

        Ok(Response::new())
    }

    pub fn unauthorize_workers(
        deps: DepsMut,
        workers: Vec<Addr>,
        service_name: String,
    ) -> Result<Response, ContractError> {
        SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        for worker in workers {
            WORKERS.update(
                deps.storage,
                (&service_name.clone(), &worker.clone()),
                |sw| -> Result<Worker, ContractError> {
                    match sw {
                        Some(worker) => Ok(Worker {
                            authorization_state: AuthorizationState::NotAuthorized,
                            ..worker
                        }),
                        None => Ok(Worker {
                            address: worker,
                            bonding_state: BondingState::Unbonded,
                            authorization_state: AuthorizationState::NotAuthorized,
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
        SERVICES
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
                    Some(worker) => {
                        let bonding_state = match worker.bonding_state {
                            BondingState::Bonded { amount }
                            | BondingState::RequestedUnbonding { amount }
                            | BondingState::Unbonding {
                                amount,
                                unbonded_at: _,
                            } => BondingState::Bonded {
                                amount: amount + bond,
                            },
                            BondingState::Unbonded {} => BondingState::Bonded { amount: bond },
                        };
                        Ok(Worker {
                            bonding_state,
                            ..worker
                        })
                    }
                    None => Ok(Worker {
                        address: info.sender,
                        bonding_state: BondingState::Bonded { amount: bond },
                        authorization_state: AuthorizationState::NotAuthorized,
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

        let worker = WORKERS
            .may_load(deps.storage, (&service_name, &info.sender))?
            .ok_or(ContractError::WorkerNotFound {})?;

        let can_unbond = true; // TODO: actually query the service to determine this value

        let bonding_state = match worker.bonding_state {
            BondingState::Bonded { amount } | BondingState::RequestedUnbonding { amount }
                if can_unbond =>
            {
                Ok(BondingState::Unbonding {
                    unbonded_at: env.block.time,
                    amount,
                })
            }
            BondingState::Bonded { amount } if !can_unbond => {
                Ok(BondingState::RequestedUnbonding { amount })
            }
            _ => Err(ContractError::InvalidBondingState(worker.bonding_state)),
        }?;

        WORKERS.save(
            deps.storage,
            (&service_name, &info.sender),
            &Worker {
                bonding_state,
                ..worker
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

        let worker = WORKERS
            .may_load(deps.storage, (&service_name, &info.sender))?
            .ok_or(ContractError::WorkerNotFound {})?;

        let bond = match worker.bonding_state {
            BondingState::Unbonding {
                amount,
                unbonded_at,
            } if unbonded_at.plus_days(service.unbonding_period_days as u64) <= env.block.time => {
                Ok(amount)
            }
            _ => Err(ContractError::InvalidBondingState(worker.bonding_state)),
        }?;

        WORKERS.save(
            deps.storage,
            (&service_name, &info.sender),
            &Worker {
                bonding_state: BondingState::Unbonded,
                ..worker
            },
        )?;

        Ok(Response::new().add_message(BankMsg::Send {
            to_address: info.sender.into(),
            amount: [Coin {
                denom: AXL_DENOMINATION.to_string(),
                amount: bond,
            }]
            .to_vec(), // TODO: isolate coins
        }))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::GetBondedWorkers {
            service_name,
            chain_name,
        } => to_binary(&query::get_bonded_workers(deps, service_name, chain_name)?)
            .map_err(|e| e.into()),
    }
}

pub mod query {
    use crate::state::{AuthorizationState, WORKERS, WORKERS_PER_CHAIN};

    use super::*;

    pub fn get_bonded_workers(
        deps: Deps,
        service_name: String,
        chain_name: String,
    ) -> Result<BondedWorkers, ContractError> {
        let service = SERVICES
            .may_load(deps.storage, &service_name)?
            .ok_or(ContractError::ServiceNotFound {})?;

        let workers = WORKERS_PER_CHAIN
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
            .collect();

        Ok(BondedWorkers { workers })
    }
}
