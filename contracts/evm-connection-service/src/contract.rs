#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
    StdResult, Uint256, Uint64,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActionMessage, InstantiateMsg};
use crate::state::{PollMetadata, ServiceInfo, POLLS, POLL_COUNTER, SERVICE_INFO};
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
        voting_threshold: msg.voting_threshold,
        min_voter_count: msg.min_voter_count,
        reward_pool: msg.reward_pool,
        voting_period: msg.voting_period,
        voting_grace_period: msg.voting_grace_period,
    };
    SERVICE_INFO.save(deps.storage, &service)?;
    POLL_COUNTER.save(deps.storage, &0);

    // TODO: register service during instantiation
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ServiceExecuteMsg<ActionMessage>,
) -> Result<Response, ContractError> {
    match msg {
        ServiceExecuteMsg::RequestWorkerAction { message } => {
            execute::request_worker_action(deps, env, message)
        }
        ServiceExecuteMsg::PostWorkerReply { reply, id } => {
            execute::post_worker_reply(deps, info, reply, id)
        }
    }
}

pub mod execute {
    use crate::state::POLL_COUNTER;

    use super::*;

    pub fn request_worker_action(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        match message {
            ActionMessage::ConfirmGatewayTxs {
                source_chain_name,
                from_nonce,
                to_nonce,
                destination_chain_name,
            } => request_confirm_gateway_txs(deps, env, message),
        }
    }

    fn initialize_poll(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<PollMetadata, ContractError> {
        let id =
            POLL_COUNTER.update(deps.storage, |mut counter| -> Result<u64, ContractError> {
                counter += 1;
                Ok(counter)
            })?;

        let service_info = SERVICE_INFO.load(deps.storage)?;
        let expires_at = env.block.height + service_info.voting_period.u64();

        let poll = PollMetadata::new(Uint64::from(id), Uint64::from(expires_at), message);

        POLLS.save(deps.storage, id, &poll)?;

        Ok(poll)
    }

    pub fn request_confirm_gateway_txs(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker ??

        if let ActionMessage::ConfirmGatewayTxs {
            source_chain_name,
            from_nonce,
            to_nonce,
            destination_chain_name,
        } = message
        {
            let poll = initialize_poll(deps, env, message)?;

            let event = Event::new("ConfirmGatewayTxStarted")
                .add_attribute("poll_id", poll.id)
                .add_attribute("source_chain", source_chain_name)
                .add_attribute("from_nonce", from_nonce)
                .add_attribute("to_nonce", to_nonce)
                .add_attribute("destination_chain_name", destination_chain_name);
            // TODO: add gateway ??
            // TODO: add poll participants
            // TODO: add confirmation height??

            Ok(Response::new().add_event(event))
        } else {
            Err(ContractError::InvalidAction {})
        }
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
            |r| -> Result<PollMetadata, ContractError> {
                match r {
                    Some(mut request) => {
                        if request.consensus_reached {
                            // TODO: no throw error, votes needed for reward
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

                        if request.voters.len()
                            >= service.voting_threshold.u64().try_into().unwrap()
                        {
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
