#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, StdResult,
    WasmQuery,
};

use crate::{
    batch::CommandBatch,
    error::ContractError,
    msg::{ExecuteMsg, GetProofResponse, InstantiateMsg, QueryMsg},
    state::{Config, COMMANDS_BATCH, CONFIG},
    types::Message,
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
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        env: Env,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        let query = gateway::msg::QueryMsg::GetMessages { message_ids };
        let messages: Vec<connection_router::msg::Message> =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: config.gateway.into(),
                msg: to_binary(&query)?,
            }))?;

        if messages.is_empty() {
            return Ok(Response::default());
        }

        let messages: Vec<Message> = messages
            .into_iter()
            .map(|msg| msg.try_into())
            .collect::<Result<Vec<Message>, ContractError>>()?;

        let command_batch =
            CommandBatch::new(env.block.height, messages, config.destination_chain_id);

        COMMANDS_BATCH.save(deps.storage, &command_batch.id, &command_batch)?;

        // TODO: start signing session

        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProof { proof_id } => to_binary(&query::get_proof(proof_id)?),
    }
}

pub mod query {
    use super::*;

    pub fn get_proof(_proof_id: String) -> StdResult<GetProofResponse> {
        todo!()
    }
}
