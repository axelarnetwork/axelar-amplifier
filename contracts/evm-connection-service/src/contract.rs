#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, CustomQuery, Deps, DepsMut, Env, Event, MessageInfo,
    QueryRequest, Response, StdResult, Uint64, WasmMsg, WasmQuery,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ActionMessage, ActionResponse, InstantiateMsg};
use crate::snapshot::Snapshot;
use crate::state::{PollMetadata, ServiceInfo, POLLS, POLL_COUNTER, SERVICE_INFO};

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
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let service = ServiceInfo {
        service_registry: msg.service_registry,
        name: msg.service_name,
        source_chain_name: msg.source_chain_name,
        gateway_address: msg.gateway_address,
        confirmation_height: msg.confirmation_height,
        voting_threshold: msg.voting_threshold,
        min_voter_count: msg.min_voter_count,
        reward_pool: msg.reward_pool,
        voting_period: msg.voting_period,
        voting_grace_period: msg.voting_grace_period,
    };
    SERVICE_INFO.save(deps.storage, &service)?;
    POLL_COUNTER.save(deps.storage, &0)?;

    let register_msg = service_registry::msg::ExecuteMsg::RegisterService {
        service_name: service.name,
        service_contract: env.contract.address,
        min_num_workers: msg.min_num_workers,
        max_num_workers: msg.max_num_workers,
        min_worker_bond: msg.min_worker_bond,
        unbonding_period: msg.unbonding_period,
        description: msg.description,
    };
    Ok(Response::default().add_message(WasmMsg::Execute {
        contract_addr: service.service_registry.into_string(),
        msg: to_binary(&register_msg)?,
        funds: vec![],
    }))
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
    use cosmwasm_std::{QuerierWrapper, Storage};
    use serde_json::to_string;

    use crate::state::Participant;

    use super::*;

    pub fn request_worker_action(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        match message {
            ActionMessage::ConfirmGatewayTxs {
                from_nonce: _,
                to_nonce: _,
            } => request_confirm_gateway_txs(deps, env, message),
        }
    }

    fn create_snapshot<'a, C: CustomQuery>(
        store: &'a mut dyn Storage,
        querier: QuerierWrapper<'a, C>,
        env: Env,
        service_info: &ServiceInfo,
        poll_id: Uint64,
    ) -> Result<Snapshot, ContractError> {
        let query_msg: RegistryQueryMsg = RegistryQueryMsg::GetActiveWorkers {
            service_name: service_info.name.to_owned(),
        };

        let active_workers: ActiveWorkers =
            querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let snapshot = Snapshot::new(
            store,
            poll_id,
            env.block.time,
            Uint64::from(env.block.height),
            active_workers,
        );

        Ok(snapshot)
    }

    fn initialize_poll<'a, C: CustomQuery>(
        store: &'a mut dyn Storage,
        querier: QuerierWrapper<'a, C>,
        env: Env,
        message: ActionMessage,
    ) -> Result<PollMetadata, ContractError> {
        let id = POLL_COUNTER.update(store, |mut counter| -> Result<u64, ContractError> {
            counter += 1;
            Ok(counter)
        })?;

        let service_info = SERVICE_INFO.load(store)?;
        let expires_at = env.block.height + service_info.voting_period.u64();

        let snapshot = create_snapshot(store, querier, env, &service_info, Uint64::from(id))?;

        let poll_metadata = PollMetadata::new(
            Uint64::from(id),
            Uint64::from(expires_at),
            snapshot,
            message,
        );

        POLLS.save(store, id, &poll_metadata)?;

        Ok(poll_metadata)
    }

    pub fn request_confirm_gateway_txs(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker ??

        let service_info = SERVICE_INFO.load(deps.storage)?;

        let poll = initialize_poll(deps.storage, deps.querier, env, message)?;

        let ActionMessage::ConfirmGatewayTxs {
            from_nonce,
            to_nonce,
        } = poll.message;

        let participants: Vec<Participant> = poll
            .snapshot
            .participants(deps.storage)
            .map(|item| {
                let (_, participant) = item.unwrap();
                participant
            })
            .collect();

        let event = Event::new("ConfirmGatewayTxStarted")
            .add_attribute("poll_id", poll.id)
            .add_attribute("source_chain", service_info.source_chain_name)
            .add_attribute("gateway_address", service_info.gateway_address)
            .add_attribute("confirmation_height", service_info.confirmation_height)
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
    use cosmwasm_std::{Coin, Decimal, Empty, Uint128, Uint256};
    use cw_multi_test::{next_block, App, AppBuilder, Contract, ContractWrapper, Executor};

    use super::*;

    const OWNER: &str = "owner";
    const GATEWAY: &str = "gateway";
    const WORKERS: [&str; 6] = [
        "worker0", "worker1", "worker2", "worker3", "worker4", "worker5",
    ];

    fn mock_app(init_funds: &[Coin]) -> App {
        AppBuilder::new().build(|router, _, storage| {
            for worker in WORKERS {
                router
                    .bank
                    .init_balance(storage, &Addr::unchecked(worker), init_funds.to_vec())
                    .unwrap();
            }
        })
    }

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
        source_chain_name: String,
        gateway_address: Addr,
        confirmation_height: Uint64,
        min_num_workers: Uint64,
        max_num_workers: Option<Uint64>,
        min_worker_bond: Uint128,
        unbonding_period: Uint128,
        description: String,
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
            source_chain_name,
            gateway_address,
            confirmation_height,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period,
            description,
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

    fn register_workers(app: &mut App, service_name: &str, registry: Addr) {
        for worker in WORKERS {
            let msg = service_registry::msg::ExecuteMsg::RegisterWorker {
                service_name: service_name.to_owned(),
                commission_rate: Uint128::from(1u8),
            };

            app.execute_contract(
                Addr::unchecked(worker),
                registry.clone(),
                &msg,
                &vec![Coin {
                    denom: "uaxl".to_string(),
                    amount: Uint128::from(100u8),
                }],
            )
            .unwrap();
        }
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
        let source_chain_name = "Ethereum".to_string();
        let gateway_address = Addr::unchecked(GATEWAY);
        let confirmation_height = Uint64::from(10u64);
        let min_num_workers = min_voter_count.clone();
        let max_num_workers = None;
        let min_worker_bond = Uint128::from(100u8);
        let unbonding_period = Uint128::from(1u8);
        let description = "EVM Connection Service".to_string();

        let service_address = instantiate_service(
            app,
            registry_addr.clone(),
            service_name.clone(),
            source_chain_name,
            gateway_address,
            confirmation_height,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period,
            description,
            voting_threshold,
            min_voter_count,
            reward_pool,
            voting_period,
            voting_grace_period,
        );
        app.update_block(next_block);
        register_workers(app, &service_name, registry_addr.clone());

        (service_address, registry_addr)
    }

    fn setup_default_test_case(app: &mut App) -> (Addr, Addr) {
        let voting_threshold = Decimal::from_ratio(1u8, 2u8);
        let min_voter_count = Uint64::from(5u64);
        let reward_pool = Addr::unchecked("reward_pool");
        let voting_period = Uint64::from(5u64);
        let voting_grace_period = Uint64::from(5u64);

        setup_test_case(
            app,
            voting_threshold,
            min_voter_count,
            reward_pool,
            voting_period,
            voting_grace_period,
        )
    }

    fn do_instantiate(deps: DepsMut) -> Response {
        let min_voter_count = Uint64::from(5u64);
        let service_name = "EVM Connection Service".to_string();
        let source_chain_name = "Ethereum".to_string();
        let gateway_address = Addr::unchecked(GATEWAY);
        let confirmation_height = Uint64::from(10u64);
        let min_num_workers = min_voter_count.clone();
        let max_num_workers = None;
        let min_worker_bond = Uint128::from(100u8);
        let unbonding_period = Uint128::from(1u8);
        let description = "EVM Connection Service".to_string();

        let info = mock_info("creator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            service_registry: Addr::unchecked("service_registry"),
            service_name,
            source_chain_name,
            gateway_address,
            confirmation_height,
            min_num_workers,
            max_num_workers,
            min_worker_bond,
            unbonding_period,
            description,
            voting_threshold: Decimal::from_ratio(1u8, 2u8),
            min_voter_count,
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

        assert_eq!(1, res.messages.len());
    }

    #[test]
    fn test_request_worker_action() {
        let mut app = mock_app(&[Coin {
            denom: "uaxl".to_string(),
            amount: Uint128::from(100u8),
        }]);

        let (service_addr, _) = setup_default_test_case(&mut app);

        let msg: ServiceExecuteMsg<ActionMessage, ActionResponse> =
            ServiceExecuteMsg::RequestWorkerAction {
                message: ActionMessage::ConfirmGatewayTxs {
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
