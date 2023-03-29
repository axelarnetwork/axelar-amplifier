use connection_router::msg::{ExecuteMsg, GetMessagesResponse, InstantiateMsg, QueryMsg};
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use crate::command::CommandType;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    let mut messages: Vec<Binary> = Vec::new();
    let command_type = CommandType::ValidateCallsHash {
        source_chain: "Ethereum".to_string(),
        calls_hash: [0u8; 32],
    };
    messages.push(to_binary(&command_type)?);

    let response: GetMessagesResponse = GetMessagesResponse { messages };
    Ok(to_binary(&response)?)
}
