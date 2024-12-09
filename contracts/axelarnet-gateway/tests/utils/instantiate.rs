use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{mock_env, mock_info, MockApi};
use cosmwasm_std::{DepsMut, Response};

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            chain_name: params::AXELARNET.parse().unwrap(),
            router_address: MockApi::default().addr_make(params::ROUTER).to_string(),
            nexus: MockApi::default().addr_make(params::NEXUS).to_string(),
        },
    )
}
