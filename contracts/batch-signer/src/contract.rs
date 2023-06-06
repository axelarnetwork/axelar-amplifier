#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Reply, Response,
    StdResult, SubMsg, WasmMsg,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    batch::CommandBatch,
    error::ContractError,
    msg::QueryMsg,
    msg::{ExecuteMsg, InstantiateMsg},
    state::COMMANDS_BATCH_QUEUE,
    state::{Config, CONFIG},
    types::Message,
};

pub const REPLY_CONSTRUCT_PROOF: u64 = 1;

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
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(deps, message_ids),
        ExecuteMsg::SignProof {
            proof_id,
            signature,
        } => execute::sign_proof(proof_id, signature),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        let submsg = SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: config.gateway.into(),
                msg: to_binary(&outgoing_gateway::msg::ExecuteMsg::FetchMessages { message_ids })?,
                funds: vec![],
            },
            REPLY_CONSTRUCT_PROOF,
        );

        Ok(Response::new().add_submessage(submsg))
    }

    pub fn sign_proof(_proof_id: String, _signature: HexBinary) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        REPLY_CONSTRUCT_PROOF => {
            let res = parse_reply_execute_data(msg)?;

            match res {
                MsgExecuteContractResponse { data: None } => Ok(Response::new()), // TODO: should this return error instead? or let the gateway handle it?
                MsgExecuteContractResponse { data: Some(data) } => {
                    let messages: Vec<connection_router::types::Message> = from_binary(&data)?;
                    reply::construct_proof(deps, env, messages)
                }
            }
        }
        _ => Err(ContractError::InvalidReplyID {}),
    }
}

pub mod reply {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        env: Env,
        messages: Vec<connection_router::types::Message>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        if messages.is_empty() {
            return Ok(Response::default());
        }

        let messages: Vec<Message> = messages
            .into_iter()
            .map(|msg| msg.try_into())
            .collect::<Result<Vec<Message>, ContractError>>()?;

        let command_batch =
            CommandBatch::new(env.block.height, messages, config.destination_chain_id);

        COMMANDS_BATCH_QUEUE.save(deps.storage, &command_batch.id, &command_batch)?;

        // TODO: start signing session

        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}
