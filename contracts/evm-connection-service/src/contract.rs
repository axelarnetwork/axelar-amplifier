#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
    StdResult, Uint64,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActionMessage, ActionResponse, InstantiateMsg};
use crate::state::{
    PollMetadata, ServiceInfo, TalliedVote, POLLS, POLL_COUNTER, SERVICE_INFO, TALLIED_VOTES,
};
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
    msg: ServiceExecuteMsg<ActionMessage, ActionResponse>,
) -> Result<Response, ContractError> {
    match msg {
        ServiceExecuteMsg::RequestWorkerAction { message } => {
            execute::request_worker_action(deps, env, message)
        }
        ServiceExecuteMsg::PostWorkerReply { reply } => {
            execute::post_worker_reply(deps, env, info, reply)
        }
    }
}

pub mod execute {
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
        } = message
        {
            let poll = initialize_poll(deps, env, message)?;

            let event = Event::new("ConfirmGatewayTxStarted")
                .add_attribute("poll_id", poll.id)
                .add_attribute("source_chain", source_chain_name)
                .add_attribute("from_nonce", from_nonce)
                .add_attribute("to_nonce", to_nonce);
            // TODO: add gateway ?? on-chain mapping
            // TODO: add poll participants
            // TODO: add confirmation height??

            Ok(Response::new().add_event(event))
        } else {
            Err(ContractError::InvalidAction {})
        }
    }

    pub fn post_worker_reply(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        reply: ActionResponse,
    ) -> Result<Response, ContractError> {
        match reply {
            ActionResponse::ConfirmGatewayTxs {
                poll_id,
                calls_hash,
            } => vote_confirm_gateway_txs(deps, env, info, reply),
        }
    }

    pub fn vote_confirm_gateway_txs(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        reply: ActionResponse,
    ) -> Result<Response, ContractError> {
        // TODO: vote validations

        if let ActionResponse::ConfirmGatewayTxs {
            poll_id,
            calls_hash,
        } = reply
        {
            TALLIED_VOTES.update(
                deps.storage,
                (poll_id.u64(), &reply),
                |v| -> Result<TalliedVote, ContractError> {
                    match v {
                        Some(tallied_vote) => todo!(),
                        None => todo!(),
                    }
                },
            );

            Ok(Response::new())
        } else {
            Err(ContractError::InvalidAction {})
        }
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
