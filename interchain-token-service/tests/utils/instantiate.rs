use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{mock_env, mock_info};
use cosmwasm_std::{DepsMut, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            governance_address: params::GOVERNANCE.to_string(),
            admin_address: params::ADMIN.to_string(),
            axelarnet_gateway_address: params::GATEWAY.to_string(),
            its_contracts: Default::default(),
        },
    )
}
