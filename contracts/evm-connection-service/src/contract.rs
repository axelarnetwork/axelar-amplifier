#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
    StdResult, Uint64,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::{ActionRequest, ServiceInfo, ACTION_REQUESTS, SERVICE_INFO};
use service_interface::msg::ActionMessage;
use service_interface::msg::ExecuteMsg as ServiceExecuteMsg;
use service_interface::msg::QueryMsg as ServiceQueryMsg;
use service_interface::msg::WorkerState;

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let service = ServiceInfo {
        name: msg.service_name,
        threshold: msg.threshold,
    };
    SERVICE_INFO.save(deps.storage, &service)?;

    // TODO: register service during instantiation
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ServiceExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ServiceExecuteMsg::RequestWorkerAction { message } => {
            execute::request_worker_action(deps, message)
        }
        ServiceExecuteMsg::PostWorkerReply { reply, id } => {
            execute::post_worker_reply(deps, info, reply, id)
        }
    }
}

pub mod execute {
    use super::*;

    pub fn request_worker_action(
        deps: DepsMut,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker

        let request = ACTION_REQUESTS.update(
            deps.storage,
            &message.command_id.to_owned(),
            |r| -> Result<ActionRequest, ContractError> {
                match r {
                    Some(_one) => Err(ContractError::ActionAlreadyRequested {}),
                    None => Ok(ActionRequest::new(message)),
                }
            },
        )?;

        let event = Event::new("request_worker_action")
            .add_attribute("message", serde_json::to_string(&request.message).unwrap());

        Ok(Response::new().add_event(event))
    }

    pub fn post_worker_reply(
        deps: DepsMut,
        info: MessageInfo,
        reply: bool,
        id: [u8; 32],
    ) -> Result<Response, ContractError> {
        // TODO: validate service has enough workers to be operational minWorkers =< workers =< maxWorkers

        let service = SERVICE_INFO.load(deps.storage)?;
        let response = Response::new();

        ACTION_REQUESTS.update(
            deps.storage,
            &id,
            |r| -> Result<ActionRequest, ContractError> {
                match r {
                    Some(mut request) => {
                        if request.consensus_reached {
                            return Err(ContractError::VotingAlreadyClosed {});
                        }

                        request
                            .voters
                            .entry(info.sender)
                            .and_modify(|v| {
                                // reduce old vote by one
                                request
                                    .votes
                                    .entry(*v)
                                    .and_modify(|oldVote| *oldVote -= Uint64::one());

                                *v = reply;
                            }) // throw an error instead?
                            .or_insert(reply);

                        // increase vote counter by one
                        *request.votes.entry(reply).or_default() += Uint64::one();

                        if request.voters.len() >= service.threshold.u64().try_into().unwrap() {
                            request.consensus_reached = true;
                            if request.votes.get(&true) > request.votes.get(&false) {
                                // TODO: add message to router in response
                            }
                        }

                        Ok(request)
                    }
                    None => Err(ContractError::InvalidRequestId {}),
                }
            },
        )?;

        Ok(response)
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: ServiceQueryMsg) -> StdResult<Binary> {
    match msg {
        ServiceQueryMsg::GetServiceName {} => to_binary(&query::get_service_name()?),
        ServiceQueryMsg::GetWorkerPublicKeys {} => to_binary(&query::get_worker_public_keys()?),
        ServiceQueryMsg::GetRewardsManager {} => to_binary(&query::get_rewards_manager()?),
        ServiceQueryMsg::GetUnbondAllowed { worker_address } => {
            to_binary(&query::get_unbond_allowed(worker_address)?)
        }
        ServiceQueryMsg::GetWorkerStatus { worker_address } => {
            to_binary(&query::get_worker_status(worker_address)?)
        }
    }
}

pub mod query {
    use super::*;

    pub fn get_service_name() -> StdResult<String> {
        todo!();
    }

    pub fn get_worker_public_keys() -> StdResult<Vec<String>> {
        todo!();
    }

    pub fn get_rewards_manager() -> StdResult<Option<Addr>> {
        todo!();
    }

    pub fn get_unbond_allowed(worker_address: Addr) -> StdResult<Option<String>> {
        todo!();
    }

    pub fn get_worker_status(worker_address: Addr) -> StdResult<WorkerState> {
        todo!();
    }
}

#[cfg(test)]
mod tests {}
