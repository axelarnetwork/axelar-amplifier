use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{message_info, mock_env};
use cosmwasm_std::{DepsMut, Response};
use router_api::{chain_name, cosmos_addr};

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::SENDER), &[]),
        InstantiateMsg {
            chain_name: chain_name!(params::AXELARNET),
            router_address: cosmos_addr!(params::ROUTER).to_string(),
            nexus: cosmos_addr!(params::NEXUS).to_string(),
        },
    )
}
