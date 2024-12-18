use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{message_info, mock_env, MockApi};
use cosmwasm_std::{DepsMut, Response};

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make("sender"), &[]),
        InstantiateMsg {
            chain_name: params::AXELARNET.parse().unwrap(),
            router_address: MockApi::default().addr_make(params::ROUTER).to_string(),
            nexus: MockApi::default().addr_make(params::NEXUS).to_string(),
        },
    )
}
