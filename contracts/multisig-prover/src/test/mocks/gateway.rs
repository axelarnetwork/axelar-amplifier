use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use gateway::msg::InstantiateMsg;
use gateway_api::msg::{ExecuteMsg, QueryMsg};

use crate::test::test_data;

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

pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetOutgoingMessages { message_ids: _ } => {
            let res = test_data::messages();
            to_json_binary(&res)
        }
    }
}
