#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, CustomQuery, Deps, DepsMut, Env, Event, MessageInfo,
    QueryRequest, Response, StdResult, Uint256, Uint64, WasmMsg, WasmQuery,
};
// use cw2::set_contract_version;

use crate::{
    command::{new_validate_calls_hash_command, CommandType},
    error::ContractError,
    msg::{ActionMessage, ActionResponse, AdminOperation, ExecuteMsg, InstantiateMsg, QueryMsg},
    poll::Poll,
    snapshot::Snapshot,
    state::{
        CommandBatch, PollMetadata, ServiceInfo, ADMIN, COMMANDS_BATCH_QUEUE, INBOUND_SETTINGS,
        OUTBOUND_SETTINGS, POLLS, POLL_COUNTER, SERVICE_INFO, SIGNING_SESSION_COUNTER,
    },
};

use service_interface::msg::WorkerState;
use service_registry::msg::ActiveWorkers;
use service_registry::msg::QueryMsg as RegistryQueryMsg;

use ethabi::{ethereum_types::U256, Token};

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
    OUTBOUND_SETTINGS.save(deps.storage, &msg.outbound_settings)?;

    POLL_COUNTER.save(deps.storage, &0)?;
    SIGNING_SESSION_COUNTER.save(deps.storage, &0)?;

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
    use cosmwasm_std::{QuerierWrapper, Storage};
    use serde_json::to_string;

    use crate::{
        multisig::{start_signing_session, WorkerSignature},
        state::{Participant, ADMIN, SIGNING_SESSIONS, WORKERS_WHITELIST},
    };

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
                    AdminOperation::WhitelistWorkers { workers } => {
                        whitelist_workers(deps.storage, workers)
                    }
                };
            }
        }

        Err(ContractError::Unauthorized {})
    }

    fn whitelist_workers(
        store: &mut dyn Storage,
        workers: Vec<Addr>,
    ) -> Result<Response, ContractError> {
        for worker in workers {
            WORKERS_WHITELIST.save(store, worker, &true)?;
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
            ActionMessage::SignCommands {} => finalize_batch(deps, env),
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
        let inbound_settings = INBOUND_SETTINGS.load(store)?;

        let expires_at = env.block.height + inbound_settings.voting_period.u64();

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
        from_nonce: Uint256,
        to_nonce: Uint256,
    ) -> Result<Response, ContractError> {
        // TODO: validate sender = worker

        let inbound_settings = INBOUND_SETTINGS.load(deps.storage)?;

        let poll = initialize_poll(deps.storage, deps.querier, env, message)?;

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
            .add_attribute("source_chain", inbound_settings.source_chain_name)
            .add_attribute("gateway_address", inbound_settings.gateway_address)
            .add_attribute("confirmation_height", inbound_settings.confirmation_height)
            .add_attribute("from_nonce", from_nonce)
            .add_attribute("to_nonce", to_nonce)
            .add_attribute("participants", to_string(&participants).unwrap());

        Ok(Response::new().add_event(event))
    }

    fn pack_batch_arguments(
        chain_id: Uint256,
        commands_ids: &[[u8; 32]],
        commands: &[String],
        commands_params: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let chain_id_token = Token::Uint(U256::from_dec_str(&chain_id.to_string()).unwrap());
        let commands_ids_tokens: Vec<Token> = commands_ids
            .iter()
            .map(|item| Token::FixedBytes(item.to_vec()))
            .collect();
        let commands_tokens: Vec<Token> = commands
            .iter()
            .map(|item| Token::String(item.clone()))
            .collect();
        let commands_params_tokens: Vec<Token> = commands_params
            .iter()
            .map(|item| Token::Bytes(item.clone()))
            .collect();

        ethabi::encode(&[
            chain_id_token,
            Token::Array(commands_ids_tokens),
            Token::Array(commands_tokens),
            Token::Array(commands_params_tokens),
        ])
    }

    fn new_command_batch(
        block_height: u64,
        destination_chain_id: Uint256,
        destination_chain_name: &str,
        messages: Vec<Binary>,
    ) -> Result<CommandBatch, ContractError> {
        let mut commands_ids: Vec<[u8; 32]> = Vec::new();
        let mut commands: Vec<String> = Vec::new();
        let mut commands_params: Vec<Vec<u8>> = Vec::new();

        for message in messages {
            // TODO: filter per gas cost

            let command_type: CommandType = from_binary(&message)?;
            let command_type_string = command_type.to_string();

            let command = match command_type {
                CommandType::ValidateCallsHash {
                    source_chain,
                    calls_hash,
                } => new_validate_calls_hash_command(
                    &source_chain,
                    destination_chain_name,
                    calls_hash,
                    destination_chain_id,
                    command_type_string,
                ),
            };

            commands_ids.push(command.command_id);
            commands.push(command.command_type);
            commands_params.push(command.params);
        }

        let data = pack_batch_arguments(
            destination_chain_id,
            &commands_ids,
            &commands,
            commands_params,
        );

        let key_id = commands.first().unwrap();

        Ok(CommandBatch::new(
            block_height,
            commands_ids,
            data,
            key_id.to_owned(),
        ))
    }

    fn finalize_batch(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
        let service_info = SERVICE_INFO.load(deps.storage)?;
        let outbound_settings = OUTBOUND_SETTINGS.load(deps.storage)?;

        let query_msg = connection_router::msg::QueryMsg::GetMessages {};
        let query_response: connection_router::msg::GetMessagesResponse =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.router_contract.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        if query_response.messages.is_empty() {
            return Ok(Response::default());
        }

        let command_batch = new_command_batch(
            env.block.height,
            outbound_settings.destination_chain_id,
            &outbound_settings.destination_chain_name,
            query_response.messages,
        )?;

        COMMANDS_BATCH_QUEUE.save(deps.storage, &command_batch.id, &command_batch)?;

        let sig_started_event = start_signing_session(
            deps.storage,
            env.block.height,
            command_batch.key_id.clone(),
            command_batch.sig_hash,
            outbound_settings.destination_chain_name.clone(),
            command_batch.id,
        )?;

        let event = Event::new("Sign")
            .add_attribute("chain", outbound_settings.destination_chain_name)
            .add_attribute("batch_id", Uint256::from_be_bytes(command_batch.id))
            .add_attribute("commands_ids", command_batch.command_ids_hex_string());

        Ok(Response::new()
            .add_event(event)
            .add_event(sig_started_event))
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
            ActionResponse::SubmitSignature {
                signing_session_id,
                signature,
            } => submit_signature(deps, env, info, signing_session_id, signature),
        }
    }

    pub fn vote(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        poll_id: Uint64,
        reply: ActionResponse,
    ) -> Result<Response, ContractError> {
        let inbound_settings = INBOUND_SETTINGS.load(deps.storage)?;
        let metadata = POLLS.load(deps.storage, poll_id.u64())?;

        let mut poll = Poll::new(metadata, deps.storage, inbound_settings);
        let vote_result = poll.vote(&info.sender, env.block.height, reply)?;

        let event = Event::new("Voted")
            .add_attribute("poll", poll.metadata.id)
            .add_attribute("voter", info.sender)
            .add_attribute("vote_result", vote_result.to_string())
            .add_attribute("state", poll.metadata.state.to_string());

        // TODO: React to poll state

        Ok(Response::new().add_event(event))
    }

    pub fn submit_signature(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        signing_session_id: Uint64,
        signature: Binary,
    ) -> Result<Response, ContractError> {
        let mut signing_session = SIGNING_SESSIONS.load(deps.storage, signing_session_id.u64())?;

        signing_session.add_signature(
            deps.storage,
            env.block.height,
            info.sender.clone(),
            WorkerSignature(signature.clone()),
        )?;

        SIGNING_SESSIONS.save(deps.storage, signing_session.id.u64(), &signing_session)?;

        let event = Event::new("SignatureSubmitted")
            .add_attribute("sig_id", signing_session.id)
            .add_attribute("participant", info.sender)
            .add_attribute("signature", signature.to_base64());

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
    use crate::state::WORKERS_WHITELIST;

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

    pub fn is_address_worker_eligible(deps: Deps, address: Addr) -> StdResult<bool> {
        let result = WORKERS_WHITELIST.may_load(deps.storage, address)?;

        if let Some(whitelist) = result {
            return Ok(whitelist);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Coin, Decimal, Empty, Uint128, Uint256};
    use cw_multi_test::{next_block, App, AppBuilder, Contract, ContractWrapper, Executor};

    use crate::msg::RegistrationParameters;
    use crate::state::{InboundSettings, OutboundSettings};

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
        outbound_settings: OutboundSettings,
    ) -> Addr {
        let service_id = app.store_code(contract_service());
        let msg = InstantiateMsg {
            service_info,
            registration_parameters,
            inbound_settings,
            outbound_settings,
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

    fn whitelist_workers(app: &mut App, service: Addr) {
        let workers: Vec<Addr> = WORKERS
            .into_iter()
            .map(|worker| Addr::unchecked(worker))
            .collect();

        let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> = ExecuteMsg::Admin {
            operation: AdminOperation::WhitelistWorkers { workers },
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
                voting_threshold: Decimal::from_ratio(1u8, 2u8),
                min_voter_count: Uint64::from(5u64),
                voting_period: Uint64::from(5u64),
                voting_grace_period: Uint64::from(5u64),
            },
            outbound_settings: OutboundSettings {
                destination_chain_id: Uint256::from(43114u16),
                destination_chain_name: "Avalanche".to_string(),
                signing_timeout: Uint64::from(1u8),
                signing_grace_period: Uint64::from(1u8),
            },
        }
    }

    fn setup_test_case(
        app: &mut App,
        service_info: Option<ServiceInfo>,
        registration_parameters: Option<RegistrationParameters>,
        inbound_settings: Option<InboundSettings>,
        outbound_settings: Option<OutboundSettings>,
    ) -> (Addr, Addr) {
        let registry_addr = instantiate_registry(app);
        app.update_block(next_block);

        let default_msg = default_instantiation_message();

        let mut service_info = service_info.unwrap_or(default_msg.service_info);
        service_info.service_registry = registry_addr.clone();

        let registration_parameters =
            registration_parameters.unwrap_or(default_msg.registration_parameters);
        let inbound_settings = inbound_settings.unwrap_or(default_msg.inbound_settings);
        let outbound_settings = outbound_settings.unwrap_or(default_msg.outbound_settings);

        let service_name = service_info.name.clone();

        let service_address = instantiate_service(
            app,
            service_info,
            registration_parameters,
            inbound_settings,
            outbound_settings,
        );
        app.update_block(next_block);

        whitelist_workers(app, service_address.clone());
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
