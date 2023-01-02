#[cfg(not(feature = "library"))]
use cosmwasm_std::DepsMut;
use cosmwasm_std::{
    entry_point, Env, Event, MessageInfo, Reply, Response, StdResult, SubMsg, SubMsgResult,
};

use crate::error::ContractError;
use crate::msg::{BatchMsg, ExecuteMsg, InstantiateMsg};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _: DepsMut,
    _: Env,
    _: MessageInfo,
    _: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _: DepsMut,
    _: Env,
    _: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Batch(msg) => Ok(dispatch(msg)),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_: DepsMut, _: Env, msg: Reply) -> StdResult<Response> {
    let response = match msg.result {
        SubMsgResult::Ok(res) => Response::default().add_events(res.events),
        SubMsgResult::Err(err) => Response::default()
            .add_event(Event::new("failed_msg").add_attribute(msg.id.to_string(), err)),
    };

    Ok(response)
}

fn dispatch(msg: BatchMsg) -> Response {
    Response::new()
        .add_messages(msg.must_succeed_msgs)
        .add_submessages(
            msg.can_fail_msgs
                .into_iter()
                .enumerate()
                .map(|(i, msg)| SubMsg::reply_always(msg, i as u64)),
        )
}
