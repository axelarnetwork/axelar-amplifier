use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response, StdResult, Storage,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::LAST_MESSAGE;
use axelarnet_gateway::AxelarExecutableMsg;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let msg = msg.ensure_permissions(deps.storage, &info.sender, match_gateway)?;
    match msg {
        ExecuteMsg::SendMessage {
            destination_chain,
            destination_address,
            message,
        } => execute_send_message(deps, env, info, destination_chain, destination_address, message),
        ExecuteMsg::Execute(AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }) => execute_receive_message(deps, env, info, cc_id, source_address, payload),
    }
}

fn match_gateway(storage: &mut dyn Storage, sender: &Addr) -> Result<ExecuteMsg, Error> {
    true
}

fn execute_send_message(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    destination_chain: String,
    destination_address: String,
    message: String,
) -> StdResult<Response> {
    // In a real implementation, you would use the axelarnet gateway here to send the message
    // For this example, we'll just emit an event
    Ok(Response::new()
        .add_attribute("action", "send_message")
        .add_attribute("destination_chain", destination_chain)
        .add_attribute("destination_address", destination_address)
        .add_attribute("message", message)
        .add_event(
            Event::new("cross_chain_message_sent")
                .add_attribute("destination_chain", destination_chain)
                .add_attribute("destination_address", destination_address)
                .add_attribute("message", message),
        ))
}

fn execute_receive_message(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _cc_id: String,
    source_address: String,
    payload: Binary,
) -> StdResult<Response> {
    let message = String::from_utf8(payload.to_vec()).map_err(|_| cosmwasm_std::StdError::generic_err("Invalid UTF-8 sequence"))?;

    // Save the received message
    LAST_MESSAGE.save(deps.storage, &message)?;

    Ok(Response::new()
        .add_attribute("action", "receive_message")
        .add_attribute("source_address", source_address)
        .add_attribute("message", message.clone())
        .add_event(
            Event::new("cross_chain_message_received")
                .add_attribute("source_address", source_address)
                .add_attribute("message", message),
        ))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::LastMessage {} => to_json_binary(&query_last_message(deps)?),
    }
}

fn query_last_message(deps: Deps) -> StdResult<String> {
    LAST_MESSAGE.load(deps.storage).or_else(|_| Ok("No message received yet".to_string()))
}
