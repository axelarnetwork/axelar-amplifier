#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::ROUTES;
use service_interface::msg::ActionMessage;

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:service-registry";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    unimplemented!();
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RouteMessage { message } => execute::route_message(deps, message),
        ExecuteMsg::UpdateRoute {
            chain_id,
            destination_contract,
        } => execute::update_route(deps, chain_id, destination_contract),
    }
}

pub mod execute {
    use super::*;

    pub fn route_message(deps: DepsMut, message: ActionMessage) -> Result<Response, ContractError> {
        let destination_contract = ROUTES.load(deps.storage, message.chain_id.u128())?;

        // TODO: add message to destination_contract
        let response = Response::new();

        Ok(response)
    }

    pub fn update_route(
        deps: DepsMut,
        chain_id: Uint128,
        destination_contract: Addr,
    ) -> Result<Response, ContractError> {
        // TODO: Auth validation

        ROUTES.save(deps.storage, chain_id.u128(), &destination_contract)?;

        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!();
}

pub mod query {
    use super::*;
}

#[cfg(test)]
mod tests {}
