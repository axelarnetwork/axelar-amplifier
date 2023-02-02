#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, from_binary, to_binary, Binary, DepsMut, Env, Event, MessageInfo, QueryRequest,
    Response, Uint256, WasmQuery,
};

use crate::{
    command::{Command, CommandType},
    msg::InstantiateMsg,
    state::{CommandBatch, ServiceInfo, COMMANDS_BATCH_QUEUE, SERVICE_INFO},
    ContractError,
};

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

pub mod execute {
    use super::*;

    fn create_validate_calls_hash_params(
        source_chain: &str,
        destination_chain: &str,
        calls_hash: [u8; 32],
    ) -> Vec<u8> {
        todo!()
    }

    fn new_validate_calls_hash_command(
        source_chain: &str,
        destination_chain: &str,
        calls_hash: [u8; 32],
        command_type: String,
    ) -> Command {
        Command {
            command_id: todo!(), // TODO: keccak of callsHash and chainId
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
    ) -> Result<Vec<u8>, ContractError> {
        todo!()
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
        )?;

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

        COMMANDS_BATCH_QUEUE.push_front(deps.storage, &command_batch)?;

        let event = Event::new("RequestSignatures")
            .add_attribute(
                "batch_pos",
                COMMANDS_BATCH_QUEUE.len(deps.storage).unwrap().to_string(),
            )
            .add_attribute("commands_ids", command_batch.command_ids_hex_string());

        Ok(Response::new().add_event(event))
    }
}
