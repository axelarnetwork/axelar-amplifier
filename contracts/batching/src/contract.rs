use crate::error::ContractError;
#[cfg(not(feature = "library"))]
use cosmwasm_std::DepsMut;
use cosmwasm_std::{entry_point, Env, MessageInfo, Reply, Response, StdResult, SubMsg};

use crate::msg::{BatchMsg, InstantiateMsg};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    todo!()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: BatchMsg,
) -> Result<Response, ContractError> {
    let response = Response::new()
        .add_messages(msg.must_succeed_msgs)
        .add_submessages(
            msg.can_fail_msgs
                .into_iter()
                .enumerate()
                .map(|(i, msg)| SubMsg::reply_always(msg, i as u64)),
        );
    Ok(response)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> StdResult<Response> {
    todo!()
}
