#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response};

use crate::contract::execute::Contract;
use crate::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Config, CONFIG},
};

mod execute;
mod query;

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
    let mut contract = Contract::new(deps);
    match msg {
        ExecuteMsg::VerifyMessages(msgs) => contract.verify_messages(msgs),
        ExecuteMsg::RouteMessages(msgs) => contract.route_messages(info.sender, msgs),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::ContractError> {
    match msg {
        QueryMsg::GetMessages { message_ids } => query::get_messages(deps, message_ids),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}
