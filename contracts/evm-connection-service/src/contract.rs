use std::collections::HashMap;

#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, Isqrt, MessageInfo, Order,
    QueryRequest, Response, StdResult, Uint256, Uint64, WasmQuery,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActionMessage, ActionResponse, InstantiateMsg};
use crate::snapshot::Snapshot;
use crate::state::{Participant, PollMetadata, ServiceInfo, POLLS, POLL_COUNTER, SERVICE_INFO};

use crate::poll::Poll;
use service_interface::msg::ExecuteMsg as ServiceExecuteMsg;
use service_interface::msg::QueryMsg as ServiceQueryMsg;
use service_interface::msg::WorkerState;
use service_registry::msg::ActiveWorker;
use service_registry::msg::QueryMsg as RegistryQueryMsg;

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
        service_registry: msg.service_registry,
        name: msg.service_name,
        voting_threshold: msg.voting_threshold,
        min_voter_count: msg.min_voter_count,
        reward_pool: msg.reward_pool,
        voting_period: msg.voting_period,
        voting_grace_period: msg.voting_grace_period,
    };
    SERVICE_INFO.save(deps.storage, &service)?;
    POLL_COUNTER.save(deps.storage, &0)?;

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
                source_chain_name: _,
                from_nonce: _,
                to_nonce: _,
            } => request_confirm_gateway_txs(deps, env, message),
        }
    }

    fn quadratic_weight(stake: Uint256) -> Uint256 {
        stake.isqrt()
    }

    fn create_snapshot(
        deps: &DepsMut,
        env: Env,
        service_info: &ServiceInfo,
    ) -> Result<Snapshot, ContractError> {
        let query_msg: RegistryQueryMsg = RegistryQueryMsg::GetActiveWorkers {
            service_name: service_info.name.to_owned(),
        };

        let active_workers: Vec<ActiveWorker> =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let mut participants: HashMap<Addr, Participant> = HashMap::new();
        let mut bonded_weight: Uint256 = Uint256::zero();

        for worker in active_workers {
            //TODO: filter jailed/tombstoned ??

            let weight = quadratic_weight(Uint256::from(worker.stake)); // TODO: apply power reduction?
            bonded_weight += weight;

            let participant = Participant {
                address: worker.address,
                weight,
            };
            participants.insert(participant.address.to_owned(), participant);
        }

        let snapshot = Snapshot::new(
            env.block.time,
            Uint64::from(env.block.height),
            participants,
            bonded_weight,
        );

        Ok(snapshot)
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

        let snapshot = create_snapshot(&deps, env, &service_info)?;

        let poll_metadata = PollMetadata::new(
            Uint64::from(id),
            Uint64::from(expires_at),
            snapshot,
            message,
        );

        POLLS.save(deps.storage, id, &poll_metadata)?;

        Ok(poll_metadata)
    }

    pub fn request_confirm_gateway_txs(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker ??

        let poll = initialize_poll(deps, env, message)?;

        let ActionMessage::ConfirmGatewayTxs {
            source_chain_name,
            from_nonce,
            to_nonce,
        } = poll.message;

        let event = Event::new("ConfirmGatewayTxStarted")
            .add_attribute("poll_id", poll.id)
            .add_attribute("source_chain", source_chain_name)
            .add_attribute("from_nonce", from_nonce)
            .add_attribute("to_nonce", to_nonce);
        // TODO: add gateway ?? on-chain mapping
        // TODO: add poll participants
        // TODO: add confirmation height??

        Ok(Response::new().add_event(event))
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
                calls_hash: _,
            } => vote(deps, env, info, poll_id, reply),
        }
    }

    pub fn vote(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        poll_id: Uint64,
        reply: ActionResponse,
    ) -> Result<Response, ContractError> {
        // TODO: validate voter

        let service_info = SERVICE_INFO.load(deps.storage)?;

        let metadata = POLLS.load(deps.storage, poll_id.u64())?;
        let mut poll = Poll::new(metadata, deps.storage, service_info);
        let vote_result = poll.vote(info.sender, env.block.height, reply)?;
        // TODO: call poll.Vote

        // TODO: emit Voted event
        // TODO: React to poll state

        todo!()
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

    pub fn get_unbond_allowed(_worker_address: Addr) -> StdResult<Option<String>> {
        todo!();
    }

    pub fn get_worker_status(_worker_address: Addr) -> StdResult<WorkerState> {
        todo!();
    }
}

#[cfg(test)]
mod tests {}
