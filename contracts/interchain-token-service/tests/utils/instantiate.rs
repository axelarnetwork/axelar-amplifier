use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{mock_env, mock_info, MockApi};
use cosmwasm_std::{DepsMut, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    let api = MockApi::default();

    contract::instantiate(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            governance_address: api.addr_make(params::GOVERNANCE).to_string(),
            admin_address: api.addr_make(params::ADMIN).to_string(),
            axelarnet_gateway_address: api.addr_make(params::GATEWAY).to_string(),
        },
    )
}
