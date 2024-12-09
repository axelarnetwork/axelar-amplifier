use axelar_core_std::nexus;
use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::msg::ExecuteMsg as GatewayExecuteMsg;
use axelarnet_gateway::{contract, AxelarExecutableMsg};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::{mock_env, mock_info, MockApi};
use cosmwasm_std::{DepsMut, HexBinary, MessageInfo, Response};
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::utils::params;

#[cw_serde]
/// simulating a contract's implementation of the `Execute` variant of `ExecuteMsg` from `axelarnet-gateway`
pub enum ExecuteMsg {
    Execute(AxelarExecutableMsg),
}

pub fn call_contract(
    deps: DepsMut,
    info: MessageInfo,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response<nexus::execute::Message>, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        info,
        GatewayExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        },
    )
}

pub fn route_from_router(
    deps: DepsMut,
    msgs: Vec<Message>,
) -> Result<Response<nexus::execute::Message>, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(MockApi::default().addr_make(params::ROUTER).as_str(), &[]),
        GatewayExecuteMsg::RouteMessages(msgs),
    )
}

pub fn execute_payload(
    deps: DepsMut,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response<nexus::execute::Message>, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        GatewayExecuteMsg::Execute { cc_id, payload }.clone(),
    )
}

pub fn route_to_router(
    deps: DepsMut,
    msgs: Vec<Message>,
) -> Result<Response<nexus::execute::Message>, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        GatewayExecuteMsg::RouteMessages(msgs),
    )
}

pub fn route_from_nexus(
    deps: DepsMut,
    msgs: Vec<nexus::execute::Message>,
) -> Result<Response<nexus::execute::Message>, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(MockApi::default().addr_make(params::NEXUS).as_str(), &[]),
        GatewayExecuteMsg::RouteMessagesFromNexus(msgs),
    )
}
