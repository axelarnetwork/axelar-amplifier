#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
};

use crate::{
    error::ContractError,
    msg::QueryMsg,
    msg::{ExecuteMsg, InstantiateMsg},
    state::{Config, CONFIG},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    CONFIG.save(
        deps.storage,
        &Config {
            gateway,
            destination_chain_id: msg.destination_chain_id,
        },
    )?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => {
            execute::construct_proof(deps, env, message_ids)
        }
        ExecuteMsg::SignProof {
            proof_id,
            signature,
        } => execute::sign_proof(proof_id, signature),
    }
}

pub mod execute {
    use cosmwasm_std::{to_binary, QueryRequest, WasmQuery};

    use crate::{command::CommandBatch, state::COMMANDS_BATCH_QUEUE, types::Message};

    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        env: Env,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        let query_msg = outgoing_gateway::msg::QueryMsg::GetMessages { message_ids };
        let messages: Vec<Message> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.gateway.into(),
            msg: to_binary(&query_msg)?,
        }))?;

        if messages.is_empty() {
            return Ok(Response::default());
        }

        let command_batch =
            CommandBatch::new(env.block.height, messages, config.destination_chain_id);

        COMMANDS_BATCH_QUEUE.save(deps.storage, &command_batch.id, &command_batch)?;

        // TODO: start signing session

        Ok(Response::new())
    }

    pub fn sign_proof(_proof_id: String, _signature: HexBinary) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}
