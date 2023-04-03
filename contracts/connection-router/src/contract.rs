#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    Uint128,
};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

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
        ExecuteMsg::RegisterDomain { domain } => execute::register_domain(deps, domain),
        ExecuteMsg::RegisterIncomingGateway {
            domain,
            contract_addr,
        } => execute::register_incoming_gateway(deps, domain, contract_addr),
        ExecuteMsg::RegisterOutgoingGateway {
            domain,
            contract_addr,
            queue_id,
        } => execute::register_outgoing_gateway(deps, domain, contract_addr, queue_id),
        ExecuteMsg::DeregisterGateway {
            domain,
            contract_addr,
        } => execute::deregister_gateway(deps, domain, contract_addr),
        ExecuteMsg::RouteMessage {
            id,
            destination_domain,
            destination_addr,
            source_addr,
            payload_hash,
        } => execute::route_message(
            deps,
            id,
            destination_domain,
            destination_addr,
            source_addr,
            payload_hash,
        ),
        ExecuteMsg::ConsumeMessages { count } => execute::consume_messages(deps, count),
    }
}

pub mod execute {

    use super::*;

    pub fn register_domain(_deps: DepsMut, _domain: String) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn register_incoming_gateway(
        _deps: DepsMut,
        _domain: String,
        _contract_addr: Addr,
    ) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn register_outgoing_gateway(
        _deps: DepsMut,
        _domain: String,
        _contract_addr: Addr,
        _queue_id: Option<Uint128>,
    ) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn deregister_gateway(
        _deps: DepsMut,
        _domain: String,
        _contract_addr: Addr,
    ) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn route_message(
        _deps: DepsMut,
        _id: String,
        _destination_domain: String,
        _destination_addr: Addr,
        _source_addr: Addr,
        _payload_hash: HexBinary,
    ) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn consume_messages(_deps: DepsMut, _count: u32) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!();
}

pub mod query {
    //use super::*;
}

#[cfg(test)]
mod tests {}
