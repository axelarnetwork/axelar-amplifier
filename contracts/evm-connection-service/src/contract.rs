use std::collections::HashMap;

#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, Isqrt, MessageInfo,
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
use service_registry::msg::ActiveWorkers;
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
    Ok(Response::default())
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

        let active_workers: ActiveWorkers =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let mut participants: HashMap<Addr, Participant> = HashMap::new();
        let mut bonded_weight: Uint256 = Uint256::zero();

        for worker in active_workers.workers {
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
            source_chain_name, // TODO: should probably be validated with list of supported chain names
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
        let service_info = SERVICE_INFO.load(deps.storage)?;
        let metadata = POLLS.load(deps.storage, poll_id.u64())?;

        let mut poll = Poll::new(metadata, deps.storage, service_info);
        let vote_result = poll.vote(&info.sender, env.block.height, reply)?;

        let event = Event::new("Voted")
            .add_attribute("poll", poll.metadata.id)
            .add_attribute("voter", info.sender)
            .add_attribute("vote_result", vote_result.to_string())
            .add_attribute("state", poll.metadata.state.to_string());

        // TODO: React to poll state

        Ok(Response::new().add_event(event))
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
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Decimal, Empty};
    use cw_multi_test::{next_block, App, Contract, ContractWrapper, Executor};

    use super::*;

    const OWNER: &str = "owner";

    fn contract_registry() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            service_registry::contract::execute,
            service_registry::contract::instantiate,
            service_registry::contract::query,
        );
        Box::new(contract)
    }

    fn contract_service() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    fn instantiate_registry(app: &mut App) -> Addr {
        let registry_id = app.store_code(contract_registry());
        let msg = service_registry::msg::InstantiateMsg {};

        app.instantiate_contract(
            registry_id,
            Addr::unchecked(OWNER),
            &msg,
            &[],
            "registry",
            None,
        )
        .unwrap()
    }

    fn instantiate_service(
        app: &mut App,
        service_registry: Addr,
        service_name: String,
        voting_threshold: Decimal,
        min_voter_count: Uint64,
        reward_pool: Addr,
        voting_period: Uint64,
        voting_grace_period: Uint64,
    ) -> Addr {
        let service_id = app.store_code(contract_service());
        let msg = InstantiateMsg {
            service_registry,
            service_name,
            voting_threshold,
            min_voter_count,
            reward_pool,
            voting_period,
            voting_grace_period,
        };
        app.instantiate_contract(
            service_id,
            Addr::unchecked(OWNER),
            &msg,
            &[],
            "evm-connection-service",
            None,
        )
        .unwrap()
    }

    fn setup_test_case(
        app: &mut App,
        voting_threshold: Decimal,
        min_voter_count: Uint64,
        reward_pool: Addr,
        voting_period: Uint64,
        voting_grace_period: Uint64,
    ) -> (Addr, Addr) {
        let registry_addr = instantiate_registry(app);
        app.update_block(next_block);

        let service_name = "EVM Connection Service".to_string();
        let service_address = instantiate_service(
            app,
            registry_addr.clone(),
            service_name,
            voting_threshold,
            min_voter_count,
            reward_pool,
            voting_period,
            voting_grace_period,
        );
        app.update_block(next_block);

        (service_address, registry_addr)
    }

    fn do_instantiate(deps: DepsMut) -> Response {
        let service_name = "EVM Connection Service".to_string();

        let info = mock_info("creator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            service_registry: Addr::unchecked("service_registry"),
            service_name,
            voting_threshold: Decimal::from_ratio(1u8, 2u8),
            min_voter_count: Uint64::from(5u64),
            reward_pool: Addr::unchecked("reward_pool"),
            voting_period: Uint64::from(5u64),
            voting_grace_period: Uint64::from(5u64),
        };

        instantiate(deps, env, info, instantiate_msg).unwrap()
    }

    #[test]
    fn test_instantiation() {
        let mut deps = mock_dependencies();

        let res = do_instantiate(deps.as_mut());

        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn test_request_worker_action() {
        let mut app = App::default();

        let voting_threshold = Decimal::from_ratio(1u8, 2u8);
        let min_voter_count = Uint64::from(5u64);
        let reward_pool = Addr::unchecked("reward_pool");
        let voting_period = Uint64::from(5u64);
        let voting_grace_period = Uint64::from(5u64);

        let (service_addr, _) = setup_test_case(
            &mut app,
            voting_threshold,
            min_voter_count,
            reward_pool,
            voting_period,
            voting_grace_period,
        );

        let msg: ServiceExecuteMsg<ActionMessage, ActionResponse> =
            ServiceExecuteMsg::RequestWorkerAction {
                message: ActionMessage::ConfirmGatewayTxs {
                    source_chain_name: "Ethereum".to_string(),
                    from_nonce: Uint256::from(0u8),
                    to_nonce: Uint256::from(5u8),
                },
            };

        let res = app
            .execute_contract(Addr::unchecked(OWNER), service_addr, &msg, &[])
            .unwrap();

        let expected_event = Event::new("ConfirmGatewayTxStarted")
            .add_attribute("poll_id", Uint64::one())
            .add_attribute("source_chain", "Ethereum")
            .add_attribute("from_nonce", Uint256::from(0u8))
            .add_attribute("to_nonce", Uint256::from(5u8));

        res.has_event(&expected_event);
    }
}
