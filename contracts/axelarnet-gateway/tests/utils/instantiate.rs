use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{mock_env, mock_info};
use cosmwasm_std::{DepsMut, Response};

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            chain_name: params::AXELARNET.parse().unwrap(),
            router_address: params::ROUTER.parse().unwrap(),
        },
    )
}
