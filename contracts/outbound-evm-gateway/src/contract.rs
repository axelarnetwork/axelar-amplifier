use auth_multisig::InitAuthModuleParameters;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Decimal, Deps, DepsMut, Env, Event, MessageInfo,
    QueryRequest, Response, StdResult, Uint256, Uint64, WasmMsg, WasmQuery,
};
// use cw2::set_contract_version;

use crate::{
    command::{new_validate_calls_hash_command, CommandType},
    error::ContractError,
    msg::{ActionMessage, ActionResponse, AdminOperation, ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{
        CommandBatch, ADMIN, AUTH_MODULE, COMMANDS_BATCH_QUEUE, OUTBOUND_SETTINGS, SERVICE_INFO,
    },
};

use auth::AuthModule;
use service_interface::msg::WorkerState;
use service_registry::msg::QueryMsg as RegistryQueryMsg;

use ethabi::{ethereum_types::U256, Token};
use std::collections::HashMap;

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
    OUTBOUND_SETTINGS.save(deps.storage, &msg.outbound_settings)?;

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
        ExecuteMsg::Admin { operation } => execute::admin_operation(deps, env, info, operation),
    }
}

pub mod execute {
    use auth_multisig::{InitializeAuthSessionParameters, SubmitWorkerValidationParameters};
    use serde_json::to_string;
    use service_registry::msg::ActiveWorkers;

    use crate::command::CommandBatchMetadata;

    use super::*;

    pub fn admin_operation(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        operation: AdminOperation,
    ) -> Result<Response, ContractError> {
        let result = ADMIN.may_load(deps.storage)?;

        if let Some(admin) = result {
            if info.sender == admin {
                return match operation {
                    AdminOperation::SetPubKeys {
                        signing_treshold,
                        pub_keys,
                    } => set_pub_keys(deps, env, signing_treshold, pub_keys),
                };
            }
        }

        Err(ContractError::Unauthorized {})
    }

    fn set_pub_keys(
        deps: DepsMut,
        env: Env,
        signing_treshold: Decimal,
        pub_keys: HashMap<Addr, Binary>,
    ) -> Result<Response, ContractError> {
        let service_info = SERVICE_INFO.load(deps.storage)?;
        let auth_module = AUTH_MODULE.load(deps.storage)?;

        let query_msg: RegistryQueryMsg = RegistryQueryMsg::GetActiveWorkers {
            service_name: service_info.name.to_owned(),
        };

        let active_workers: ActiveWorkers =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        auth_module
            .set_pub_keys(deps, env.block, active_workers, signing_treshold, pub_keys)
            .unwrap(); // TODO: convert AuthError to ContractError

        Ok(Response::default())
    }

    pub fn request_worker_action(
        deps: DepsMut,
        env: Env,
        message: ActionMessage,
    ) -> Result<Response, ContractError> {
        match message {
            ActionMessage::SignCommands {} => finalize_batch(deps, env),
        }
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
                )?,
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

        Ok(CommandBatch::new(block_height, commands_ids, data))
    }

    fn finalize_batch(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
        let outbound_settings = OUTBOUND_SETTINGS.load(deps.storage)?;

        let auth_module = AUTH_MODULE.load(deps.storage)?;
        let service_info = SERVICE_INFO.load(deps.storage)?;

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

        let metadata = CommandBatchMetadata {
            chain_name: outbound_settings.destination_chain_name.clone(),
            command_batch_id: command_batch.id,
        };

        let init_auth_session_parameters = InitializeAuthSessionParameters {
            store: deps.storage,
            block_height: env.block.height,
            payload_hash: command_batch.sig_hash,
            metadata: to_binary(&metadata)?,
        };

        let signing_session = auth_module
            .initialize_auth_session(init_auth_session_parameters)
            .unwrap(); // TODO: convert AuthError to ContractError

        let pub_keys: Vec<Binary> = signing_session
            .key
            .pub_keys
            .into_iter()
            .map(|item| {
                let (_, pub_key) = item;
                pub_key
            })
            .collect();

        let sig_started_event = Event::new("SigningStarted")
            .add_attribute("sig_id", signing_session.id)
            .add_attribute("key_id", signing_session.key.id)
            .add_attribute("pub_keys", to_string(&pub_keys).unwrap())
            .add_attribute("payload_hash", hex::encode(command_batch.sig_hash));

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
            ActionResponse::SubmitSignature {
                signing_session_id,
                signature,
            } => submit_signature(deps, env, info, signing_session_id, signature),
        }
    }

    pub fn submit_signature(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        signing_session_id: Uint64,
        signature: Binary,
    ) -> Result<Response, ContractError> {
        let auth_module = AUTH_MODULE.load(deps.storage)?;

        let parameters = SubmitWorkerValidationParameters {
            store: deps.storage,
            signing_session_id,
            signer: info.sender.clone(),
            block_height: env.block.height,
            signature: signature.clone(),
        };

        auth_module.submit_worker_validation(parameters).unwrap(); // TODO: convert AuthError to ContractError

        let event = Event::new("SignatureSubmitted")
            .add_attribute("sig_id", signing_session_id)
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
    use auth_multisig::AuthMultisig;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Coin, Empty, Uint128, Uint256};
    use cw_multi_test::{next_block, App, AppBuilder, Contract, ContractWrapper, Executor};

    use crate::msg::RegistrationParameters;
    use crate::state::{OutboundSettings, ServiceInfo};

    use super::*;

    const OWNER: &str = "owner";
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
        outbound_settings: OutboundSettings,
        auth_module: AuthMultisig,
    ) -> Addr {
        let service_id = app.store_code(contract_service());
        let msg = InstantiateMsg {
            service_info,
            registration_parameters,
            outbound_settings,
            auth_module,
        };

        app.instantiate_contract(
            service_id,
            Addr::unchecked(OWNER),
            &msg,
            &[],
            "outbound-evm-gateway",
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
            outbound_settings: OutboundSettings {
                destination_chain_id: Uint256::from(43114u16),
                destination_chain_name: "Avalanche".to_string(),
            },
            auth_module: AuthMultisig {
                signing_timeout: Uint64::from(1u8),
                signing_grace_period: Uint64::from(1u8),
            },
        }
    }

    fn setup_test_case(
        app: &mut App,
        service_info: Option<ServiceInfo>,
        registration_parameters: Option<RegistrationParameters>,
        outbound_settings: Option<OutboundSettings>,
        auth_module: Option<AuthMultisig>,
    ) -> (Addr, Addr) {
        let registry_addr = instantiate_registry(app);
        app.update_block(next_block);

        let default_msg = default_instantiation_message();

        let mut service_info = service_info.unwrap_or(default_msg.service_info);
        service_info.service_registry = registry_addr.clone();

        let registration_parameters =
            registration_parameters.unwrap_or(default_msg.registration_parameters);
        let outbound_settings = outbound_settings.unwrap_or(default_msg.outbound_settings);
        let auth_module = auth_module.unwrap_or(default_msg.auth_module);

        let service_name = service_info.name.clone();

        let service_address = instantiate_service(
            app,
            service_info,
            registration_parameters,
            outbound_settings,
            auth_module,
        );
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

        let (_service_addr, _) = setup_test_case(&mut app, None, None, None, None);

        let _msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
            ExecuteMsg::RequestWorkerAction {
                message: ActionMessage::SignCommands {},
            };

        // TODO:
    }
}
