use crate::{
    command::{Command, CommandType},
    msg::{ActionMessage, InstantiateMsg},
    state::{CommandBatch, ServiceInfo, COMMANDS_BATCH_QUEUE, SERVICE_INFO},
    ContractError,
};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, DepsMut, Env, Event, MessageInfo, QueryRequest, Response,
    Uint256, WasmQuery,
};
use ethabi::{ethereum_types::U256, Bytes, FixedBytes, Token};
use sha3::{Digest, Keccak256};

const VALIDATE_CALLS_HASH_MAX_GAS_COST: u32 = 100000;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let service = ServiceInfo {
        router_contract: msg.router_contract,
        destination_chain_id: msg.destination_chain_id,
        destination_chain_name: msg.destination_chain_name,
    };

    SERVICE_INFO.save(deps.storage, &service)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: service_interface::msg::ExecuteMsg<ActionMessage, ()>,
) -> Result<Response, ContractError> {
    match msg {
        service_interface::msg::ExecuteMsg::RequestWorkerAction { message } => {
            execute::request_worker_action(deps, env, message)
        }
        service_interface::msg::ExecuteMsg::PostWorkerReply { reply: _ } => todo!(),
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
            ActionMessage::RequestWorkerSignatures {} => finalize_batch(deps, env),
        }
    }

    fn create_validate_calls_hash_params(
        source_chain: &str,
        destination_chain: &str,
        calls_hash: [u8; 32],
    ) -> Vec<u8> {
        let source_chain_token = Token::String(source_chain.to_string());
        let destination_chain_token = Token::String(destination_chain.to_string());
        let calls_hash_token = Token::FixedBytes(FixedBytes::from(calls_hash.to_vec()));

        ethabi::encode(&[
            source_chain_token,
            destination_chain_token,
            calls_hash_token,
        ])
    }

    fn new_validate_calls_hash_command(
        source_chain: &str,
        destination_chain: &str,
        calls_hash: [u8; 32],
        destination_chain_id: Uint256,
        command_type: String,
    ) -> Command {
        let chain_id_bytes = to_binary(&destination_chain_id).unwrap().to_vec();

        let mut hasher = Keccak256::new();
        hasher.update(source_chain);
        hasher.update(destination_chain);
        hasher.update(calls_hash);
        hasher.update(chain_id_bytes);
        let command_id: [u8; 32] = hasher
            .finalize()
            .as_slice()
            .try_into()
            .expect("Wrong length");

        Command {
            command_id,
            params: create_validate_calls_hash_params(source_chain, destination_chain, calls_hash),
            max_gas_cost: VALIDATE_CALLS_HASH_MAX_GAS_COST, // TODO: needs to be used
            command_type,
        }
    }

    fn pack_batch_arguments(
        chain_id: Uint256,
        commands_ids: &Vec<[u8; 32]>,
        commands: Vec<String>,
        commands_params: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let chain_id_token = Token::Uint(U256::from_dec_str(&chain_id.to_string()).unwrap());
        let commands_ids_tokens: Vec<Token> = commands_ids
            .iter()
            .map(|item| Token::FixedBytes(FixedBytes::from(item.to_vec())))
            .collect();
        let commands_tokens: Vec<Token> = commands
            .iter()
            .map(|item| Token::String(item.clone()))
            .collect();
        let commands_params_tokens: Vec<Token> = commands_params
            .iter()
            .map(|item| Token::Bytes(Bytes::from(item.clone())))
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
        destination_chain_name: String,
        messages: Vec<Binary>,
    ) -> Result<CommandBatch, ContractError> {
        let mut commands_ids: Vec<[u8; 32]> = Vec::new();
        let mut commands: Vec<String> = Vec::new();
        let mut commands_params: Vec<Vec<u8>> = Vec::new();

        for message in messages {
            let command_type: CommandType = from_binary(&message)?;
            let command_type_string = command_type.to_string();

            let command = match command_type {
                CommandType::ValidateCallsHash {
                    source_chain,
                    calls_hash,
                } => new_validate_calls_hash_command(
                    &source_chain,
                    &destination_chain_name,
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
            commands,
            commands_params,
        );

        Ok(CommandBatch::new(block_height, commands_ids, data))
    }

    fn finalize_batch(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
        let service_info = SERVICE_INFO.load(deps.storage)?;

        let query_msg = connection_router::msg::QueryMsg::GetMessages {};
        let query_response: connection_router::msg::GetMessagesResponse =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: service_info.router_contract.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let command_batch = new_command_batch(
            env.block.height,
            service_info.destination_chain_id,
            service_info.destination_chain_name,
            query_response.messages,
        )?;

        COMMANDS_BATCH_QUEUE.save(deps.storage, &command_batch.id, &command_batch)?;

        let event = Event::new("RequestSignatures")
            .add_attribute("batch_id", Uint256::from_be_bytes(command_batch.id))
            .add_attribute("commands_ids", command_batch.command_ids_hex_string());

        Ok(Response::new().add_event(event))
    }
}
