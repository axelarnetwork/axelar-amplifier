#[cfg(not(feature = "library"))]
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, entry_point, to_binary};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ActiveWorker};
use crate::state::{SERVICES, Service};

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

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
    _info: MessageInfo,
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
        ExecuteMsg::AddRewards { service_name, rewards } => execute::add_rewards(),
        ExecuteMsg::RegisterWorker {
            service_name,
            worker_address,
            bond_amount,
            commission_rate
        } => execute::register_worker(),
        ExecuteMsg::DeregisterWorker { service_name, worker_address } => execute::deregister_worker(),
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
        num_workers: u128,
        min_worker_bond: u128,
        unbonding_period: u128,
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

    pub fn add_rewards() -> Result<Response, ContractError> {

        Ok(Response::new())
    }

    pub fn register_worker() -> Result<Response, ContractError> {

        Ok(Response::new())
    }

    pub fn deregister_worker() -> Result<Response, ContractError> {

        Ok(Response::new())
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
