#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{Config, GatewayStore, Store};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let nexus = deps.api.addr_validate(&msg.nexus)?;
    let router = deps.api.addr_validate(&msg.router)?;

    GatewayStore::new(deps.storage).store_config(Config { nexus, router });

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let store = GatewayStore::new(deps.storage);
    let config = store.load_config();

    match msg {
        ExecuteMsg::VerifyMessages(_) => unimplemented!(),
        ExecuteMsg::RouteMessages(_msgs)
            if info.sender == config.nexus || info.sender == config.router =>
        {
            todo!()
        }
        _ => Err(ContractError::Unauthorized)?,
    }
}
