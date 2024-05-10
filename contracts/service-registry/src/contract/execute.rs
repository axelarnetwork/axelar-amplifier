use crate::state;
use crate::state::{AuthorizationState, CHAINS_PER_WORKER, WORKERS};
use router_api::ChainName;

use super::*;

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn register_service(
    deps: DepsMut,
    service_name: String,
    coordinator_contract: Addr,
    min_num_workers: u16,
    max_num_workers: Option<u16>,
    min_worker_bond: Uint128,
    bond_denom: String,
    unbonding_period_days: u16,
    description: String,
) -> Result<Response, ContractError> {
    let key = &service_name.clone();

    SERVICES.update(
        deps.storage,
        key,
        |service| -> Result<Service, ContractError> {
            match service {
                None => Ok(Service {
                    name: service_name,
                    coordinator_contract,
                    min_num_workers,
                    max_num_workers,
                    min_worker_bond,
                    bond_denom,
                    unbonding_period_days,
                    description,
                }),
                _ => Err(ContractError::ServiceAlreadyExists),
            }
        },
    )?;

    // Response with attributes? event?
    Ok(Response::new())
}

pub fn update_worker_authorization_status(
    deps: DepsMut,
    workers: Vec<Addr>,
    service_name: String,
    auth_state: AuthorizationState,
) -> Result<Response, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    for worker in workers {
        WORKERS.update(
            deps.storage,
            (&service_name, &worker.clone()),
            |sw| -> Result<Worker, ContractError> {
                match sw {
                    Some(mut worker) => {
                        worker.authorization_state = auth_state.clone();
                        Ok(worker)
                    }
                    None => Ok(Worker {
                        address: worker,
                        bonding_state: BondingState::Unbonded,
                        authorization_state: auth_state.clone(),
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
        .ok_or(ContractError::ServiceNotFound)?;

    let bond = if !info.funds.is_empty() {
        info.funds
            .iter()
            .find(|coin| coin.denom == service.bond_denom)
            .ok_or(ContractError::WrongDenom)?
            .amount
    } else {
        Uint128::zero() // sender can rebond currently unbonding funds by just sending no new funds
    };

    WORKERS.update(
        deps.storage,
        (&service_name.clone(), &info.sender.clone()),
        |sw| -> Result<Worker, ContractError> {
            match sw {
                Some(worker) => Ok(worker.add_bond(bond)?),
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

pub fn register_chains_support(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
    chains: Vec<ChainName>,
) -> Result<Response, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    WORKERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::WorkerNotFound)?;

    state::register_chains_support(deps.storage, service_name.clone(), chains, info.sender)?;

    Ok(Response::new())
}

pub fn deregister_chains_support(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
    chains: Vec<ChainName>,
) -> Result<Response, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    WORKERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::WorkerNotFound)?;

    state::deregister_chains_support(deps.storage, service_name.clone(), chains, info.sender)?;

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
        .ok_or(ContractError::ServiceNotFound)?;

    let worker = WORKERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::WorkerNotFound)?;

    let chains = CHAINS_PER_WORKER
        .may_load(deps.storage, (&service_name, &worker.address))?
        .unwrap_or_default();

    let query = coordinator::msg::QueryMsg::CheckWorkerCanUnbond {
        worker_address: worker.address.clone(),
        chains: chains.clone(),
    };
    let can_unbond = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: service.coordinator_contract.into(),
        msg: to_binary(&query)?,
    }))?;

    let worker = worker.unbond(can_unbond, env.block.time)?;

    WORKERS.save(deps.storage, (&service_name, &info.sender), &worker)?;

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
        .ok_or(ContractError::ServiceNotFound)?;

    let worker = WORKERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::WorkerNotFound)?;

    let (worker, released_bond) =
        worker.claim_stake(env.block.time, service.unbonding_period_days as u64)?;

    WORKERS.save(deps.storage, (&service_name, &info.sender), &worker)?;

    Ok(Response::new().add_message(BankMsg::Send {
        to_address: info.sender.into(),
        amount: [Coin {
            denom: service.bond_denom,
            amount: released_bond,
        }]
        .to_vec(), // TODO: isolate coins
    }))
}
