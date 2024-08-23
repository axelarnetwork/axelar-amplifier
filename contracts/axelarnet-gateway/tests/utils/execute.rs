use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::ExecuteMsg;
use cosmwasm_std::testing::{mock_env, mock_info};
use cosmwasm_std::{DepsMut, HexBinary, Response};
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::utils::params;

pub fn call_contract(
    deps: DepsMut,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::CallContract {
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
        mock_info(params::ROUTER, &[]),
        ExecuteMsg::RouteMessages(msgs),
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
        mock_info("sender", &[]),
        ExecuteMsg::Execute { cc_id, payload }.clone(),
    )
}
