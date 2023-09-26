#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use error_stack::Report;

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Config, CONFIG, OUTGOING_MESSAGES},
};

use self::execute::{route_incoming_messages, route_outgoing_messages, verify_messages};

mod execute;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let router = deps.api.addr_validate(&msg.router_address)?;
    let verifier = deps.api.addr_validate(&msg.verifier_address)?;

    CONFIG.save(deps.storage, &Config { verifier, router })?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages(msgs) => verify_messages(deps, msgs),
        ExecuteMsg::RouteMessages(msgs) => {
            let router = CONFIG.load(deps.storage)?.router;
            if info.sender == router {
                route_outgoing_messages(deps, msgs).map_err(Report::from)
            } else {
                route_incoming_messages(deps, msgs)
            }
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMessages {
            message_ids: cross_chain_ids,
        } => {
            let mut msgs = vec![];

            for id in cross_chain_ids {
                msgs.push(OUTGOING_MESSAGES.load(deps.storage, id)?);
            }

            to_binary(&msgs)
        }
    }
}
