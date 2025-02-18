use axelar_core_std::nexus;
use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::msg::ExecuteMsg as GatewayExecuteMsg;
use axelarnet_gateway::{contract, AxelarExecutableMsg};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::{message_info, mock_env, MockApi};
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
) -> Result<Response, ContractError> {
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

pub fn route_from_router(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make(params::ROUTER), &[]),
        GatewayExecuteMsg::RouteMessages(msgs),
    )
}

pub fn execute_payload(
    deps: DepsMut,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make("sender"), &[]),
        GatewayExecuteMsg::Execute { cc_id, payload }.clone(),
    )
}

pub fn route_to_router(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make("sender"), &[]),
        GatewayExecuteMsg::RouteMessages(msgs),
    )
}

pub fn route_from_nexus(
    deps: DepsMut,
    msgs: Vec<nexus::execute::Message>,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make(params::NEXUS), &[]),
        GatewayExecuteMsg::RouteMessagesFromNexus(msgs),
    )
}
