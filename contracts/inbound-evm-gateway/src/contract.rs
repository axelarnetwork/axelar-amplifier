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
    msg::{
        ActionMessage, ActionResponse, AdminOperation, ExecuteMsg, InstantiateMsg, QueryMsg,
        WorkerVotingPower,
    },
    state::{ADMIN, AUTH_MODULE, INBOUND_SETTINGS, SERVICE_INFO, WORKERS_VOTING_POWER},
};

use auth::AuthModule;
use auth_vote::{InitializeAuthSessionParameters, SubmitWorkerValidationParameters};
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

        let (poll, vote_result) = auth_module.submit_worker_validation(parameters).unwrap(); // TODO: convert to AuthError to ContractError

        let event = Event::new("Voted")
            .add_attribute("poll", poll.id)
            .add_attribute("voter", info.sender)
            .add_attribute("vote_result", vote_result.to_string())
            .add_attribute("state", poll.state.to_string());

        Ok(Response::new().add_event(event))
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
    use auth_vote::AuthVoting;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Coin, Decimal, Empty, Uint128, Uint256};
    use cw_multi_test::{next_block, App, AppBuilder, Contract, ContractWrapper, Executor};

    use crate::msg::{RegistrationParameters, WorkerVotingPower};
    use crate::state::{InboundSettings, ServiceInfo};

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
        service_info: ServiceInfo,
        registration_parameters: RegistrationParameters,
        inbound_settings: InboundSettings,
        auth_module: AuthVoting,
    ) -> Addr {
        let service_id = app.store_code(contract_service());
        let msg = InstantiateMsg {
            service_info,
            registration_parameters,
            inbound_settings,
            auth_module,
        };

        app.instantiate_contract(
            service_id,
            Addr::unchecked(OWNER),
            &msg,
            &[],
            "inbound-evm-gateway",
            None,
        )
        .unwrap()
    }

    fn update_workers_voting_power(app: &mut App, service: Addr) {
        let workers: Vec<WorkerVotingPower> = WORKERS
            .into_iter()
            .map(|worker| WorkerVotingPower {
                worker: Addr::unchecked(worker),
                voting_power: Uint256::one(),
            })
            .collect();

        let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> = ExecuteMsg::Admin {
            operation: AdminOperation::UpdateWorkersVotingPower { workers },
        };

        app.execute_contract(Addr::unchecked(OWNER), service, &msg, &[])
            .unwrap();
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

    fn default_instantiation_message() -> InstantiateMsg {
        InstantiateMsg {
            service_info: ServiceInfo {
                service_registry: Addr::unchecked("service_registry"),
                name: "EVM Connection Service".to_string(),
                reward_pool: Addr::unchecked("reward_pool"),
                router_contract: Addr::unchecked("router"),
            },
            registration_parameters: RegistrationParameters {
                description: "EVM Connection Service".to_string(),
                min_num_workers: Uint64::from(5u64),
                max_num_workers: None,
                min_worker_bond: Uint128::from(100u8),
                unbonding_period: Uint128::from(1u8),
            },
            inbound_settings: InboundSettings {
                source_chain_name: "Ethereum".to_string(),
                gateway_address: Addr::unchecked(GATEWAY),
                confirmation_height: Uint64::from(10u64),
            },
            auth_module: AuthVoting {
                voting_threshold: Decimal::from_ratio(1u8, 2u8),
                min_voter_count: Uint64::from(5u64),
                voting_period: Uint64::from(5u64),
                voting_grace_period: Uint64::from(5u64),
            },
        }
    }

    fn setup_test_case(
        app: &mut App,
        service_info: Option<ServiceInfo>,
        registration_parameters: Option<RegistrationParameters>,
        inbound_settings: Option<InboundSettings>,
        auth_module: Option<AuthVoting>,
    ) -> (Addr, Addr) {
        let registry_addr = instantiate_registry(app);
        app.update_block(next_block);

        let default_msg = default_instantiation_message();

        let mut service_info = service_info.unwrap_or(default_msg.service_info);
        service_info.service_registry = registry_addr.clone();

        let registration_parameters =
            registration_parameters.unwrap_or(default_msg.registration_parameters);
        let inbound_settings = inbound_settings.unwrap_or(default_msg.inbound_settings);
        let auth_module = auth_module.unwrap_or(default_msg.auth_module);

        let service_name = service_info.name.clone();

        let service_address = instantiate_service(
            app,
            service_info,
            registration_parameters,
            inbound_settings,
            auth_module,
        );
        app.update_block(next_block);

        update_workers_voting_power(app, service_address.clone());
        app.update_block(next_block);

        register_workers(app, &service_name, registry_addr.clone());

        (service_address, registry_addr)
    }

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

    #[test]
    fn test_request_worker_action() {
        let mut app = mock_app(&[Coin {
            denom: "uaxl".to_string(),
            amount: Uint128::from(100u8),
        }]);

        let (service_addr, _) = setup_test_case(&mut app, None, None, None, None);

        let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
            ExecuteMsg::RequestWorkerAction {
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
