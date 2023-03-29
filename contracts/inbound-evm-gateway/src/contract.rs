use auth_vote::InitAuthModuleParameters;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, QueryRequest, Response,
    StdResult, Storage, Uint256, Uint64, WasmMsg, WasmQuery,
};
// use cw2::set_contract_version;

use crate::{
    error::ContractError,
    handlers::{completed_poll_handler, failed_poll_handler, pending_poll_handler},
    msg::{
        ActionMessage, ActionResponse, AdminOperation, ExecuteMsg, InstantiateMsg, QueryMsg,
        WorkerVotingPower,
    },
    state::{ADMIN, AUTH_MODULE, INBOUND_SETTINGS, SERVICE_INFO, WORKERS_VOTING_POWER},
};

use auth::AuthModule;
use auth_vote::{
    FinalizePendingSessionsParameters, InitializeAuthSessionParameters, Poll,
    SubmitWorkerValidationParameters,
};
use serde_json::to_string;
use service_interface::msg::WorkerState;
use service_registry::msg::ActiveWorkers;
use service_registry::msg::QueryMsg as RegistryQueryMsg;
use service_registry::state::Worker;

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    ADMIN.save(deps.storage, &info.sender)?;
    SERVICE_INFO.save(deps.storage, &msg.service_info)?;
    INBOUND_SETTINGS.save(deps.storage, &msg.inbound_settings)?;

    AUTH_MODULE.save(deps.storage, &msg.auth_module)?;
    msg.auth_module.init_auth_module(InitAuthModuleParameters {
        store: deps.storage,
    })?;

    let register_msg = service_registry::msg::ExecuteMsg::RegisterService {
        service_name: msg.service_info.name,
        service_contract: env.contract.address,
        min_num_workers: msg.registration_parameters.min_num_workers,
        max_num_workers: msg.registration_parameters.max_num_workers,
        min_worker_bond: msg.registration_parameters.min_worker_bond,
        unbonding_period: msg.registration_parameters.unbonding_period,
        description: msg.registration_parameters.description,
    };
    Ok(Response::default().add_message(WasmMsg::Execute {
        contract_addr: msg.service_info.service_registry.into_string(),
        msg: to_binary(&register_msg)?,
        funds: vec![],
    }))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation>,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RequestWorkerAction { message } => {
            execute::request_worker_action(deps, env, message)
        }
        ExecuteMsg::PostWorkerReply { reply } => execute::post_worker_reply(deps, env, info, reply),
        ExecuteMsg::FinalizeActions {} => execute::finalize_actions(deps, env),
        ExecuteMsg::Admin { operation } => execute::admin_operation(deps, info, operation),
    }
}

pub mod execute {
    use super::*;

    pub fn admin_operation(
        deps: DepsMut,
        info: MessageInfo,
        operation: AdminOperation,
    ) -> Result<Response, ContractError> {
        let result = ADMIN.may_load(deps.storage)?;

        if let Some(admin) = result {
            if info.sender == admin {
                return match operation {
                    AdminOperation::UpdateWorkersVotingPower { workers } => {
                        update_workers_voting_power(deps.storage, workers)
                    }
                };
            }
        }

        Err(ContractError::Unauthorized {})
    }

    fn update_workers_voting_power(
        store: &mut dyn Storage,
        workers: Vec<WorkerVotingPower>,
    ) -> Result<Response, ContractError> {
        for worker_power in workers {
            WORKERS_VOTING_POWER.save(store, worker_power.worker, &worker_power.voting_power)?;
        }

        Ok(Response::default())
    }

    pub fn request_worker_action(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        match message {
            ActionMessage::ConfirmGatewayTxs {
                from_nonce,
                to_nonce,
            } => request_confirm_gateway_txs(deps, env, message, from_nonce, to_nonce),
        }
    }

    pub fn request_confirm_gateway_txs(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
        from_nonce: Uint256,
        to_nonce: Uint256,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker

        let inbound_settings = INBOUND_SETTINGS.load(deps.storage)?;

        let auth_module = AUTH_MODULE.load(deps.storage)?;
        let service_info = SERVICE_INFO.load(deps.storage)?;

        let query_msg: RegistryQueryMsg = RegistryQueryMsg::GetActiveWorkers {
            service_name: service_info.name.to_owned(),
        };

        let active_workers: ActiveWorkers =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let weight_fn = &|deps: &DepsMut, worker: &Worker| -> Option<Uint256> {
            WORKERS_VOTING_POWER
                .may_load(deps.storage, worker.address.clone())
                .unwrap()
        };

        let init_auth_session_parameters = InitializeAuthSessionParameters {
            deps,
            block: env.block,
            active_workers,
            message: to_binary(&message)?,
            filter_fn: &|_, _| true,
            weight_fn,
        };

        let poll = auth_module
            .initialize_auth_session(init_auth_session_parameters)
            .unwrap(); // TODO: convert AuthError to ContractError

        let participants = poll.snapshot.participants;

        let event = Event::new("ConfirmGatewayTxStarted")
            .add_attribute("poll_id", poll.id)
            .add_attribute("source_chain", inbound_settings.source_chain_name)
            .add_attribute("gateway_address", inbound_settings.gateway_address)
            .add_attribute("confirmation_height", inbound_settings.confirmation_height)
            .add_attribute("from_nonce", from_nonce)
            .add_attribute("to_nonce", to_nonce)
            .add_attribute("participants", to_string(&participants).unwrap());

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
        let auth_module = AUTH_MODULE.load(deps.storage)?;

        let parameters = SubmitWorkerValidationParameters {
            store: deps.storage,
            poll_id,
            voter: info.sender.clone(),
            block_height: env.block.height,
            vote: to_binary(&reply)?,
        };

        let (poll, vote_result) = auth_module.submit_worker_validation(parameters).unwrap(); // TODO: convert AuthError to ContractError

        let event = Event::new("Voted")
            .add_attribute("poll_id", poll.id)
            .add_attribute("voter", info.sender)
            .add_attribute("vote_result", vote_result.to_string())
            .add_attribute("state", poll.state.to_string());

        Ok(Response::new().add_event(event))
    }

    pub fn finalize_actions(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
        let auth_module = AUTH_MODULE.load(deps.storage)?;
        let settings = INBOUND_SETTINGS.load(deps.storage)?;
        let service_info = SERVICE_INFO.load(deps.storage)?;

        let router_address = service_info.router_contract.into_string();

        let mut expired_polls_events: Vec<Event> = Vec::new();
        let mut failed_polls_events: Vec<Event> = Vec::new();
        let mut completed_polls_events: Vec<Event> = Vec::new();

        let mut router_messages: Vec<WasmMsg> = Vec::new();

        let parameters = FinalizePendingSessionsParameters {
            store: deps.storage,
            limit: settings.finalize_actions_limit,
            block_height: env.block.height,
            pending_poll_handler: &mut |poll: &Poll| {
                expired_polls_events.push(pending_poll_handler(poll, &settings.source_chain_name));
            },
            failed_poll_handler: &mut |poll: &Poll| {
                failed_polls_events.push(failed_poll_handler(poll, &settings.source_chain_name));
            },
            completed_poll_handler: &mut |poll: &Poll| {
                let (msg, event) =
                    completed_poll_handler(poll, &settings.source_chain_name, &router_address);

                router_messages.push(msg);
                completed_polls_events.push(event);
            },
        };

        auth_module.finalize_open_sessions(parameters).unwrap(); // TODO: convert AuthError to ContractError

        Ok(Response::new()
            .add_events(expired_polls_events)
            .add_events(failed_polls_events)
            .add_events(completed_polls_events)
            .add_messages(router_messages))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetServiceName {} => to_binary(&query::get_service_name()?),
        QueryMsg::GetWorkerPublicKeys {} => to_binary(&query::get_worker_public_keys()?),
        QueryMsg::GetRewardsManager {} => to_binary(&query::get_rewards_manager()?),
        QueryMsg::GetUnbondAllowed { worker_address } => {
            to_binary(&query::get_unbond_allowed(worker_address)?)
        }
        QueryMsg::GetWorkerStatus { worker_address } => {
            to_binary(&query::get_worker_status(worker_address)?)
        }
        QueryMsg::IsAddressWorkerEligible { address } => {
            to_binary(&query::is_address_worker_eligible(deps, address)?)
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

    pub fn is_address_worker_eligible(_deps: Deps, _address: Addr) -> StdResult<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::utils::setup::default_instantiation_message;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    use super::*;

    fn do_instantiate(deps: DepsMut) -> Response {
        let info = mock_info("creator", &[]);
        let env = mock_env();

        instantiate(deps, env, info, default_instantiation_message()).unwrap()
    }

    #[test]
    fn test_instantiation() {
        let mut deps = mock_dependencies();

        let res = do_instantiate(deps.as_mut());

        assert_eq!(1, res.messages.len());
    }
}
