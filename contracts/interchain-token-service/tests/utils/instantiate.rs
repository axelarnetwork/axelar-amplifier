use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{message_info, mock_env};
use cosmwasm_std::{DepsMut, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;
use router_api::cosmos_addr;

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::SENDER), &[]),
        InstantiateMsg {
            governance_address: cosmos_addr!(params::GOVERNANCE).to_string(),
            admin_address: cosmos_addr!(params::ADMIN).to_string(),
            axelarnet_gateway_address: cosmos_addr!(params::GATEWAY).to_string(),
            operator_address: cosmos_addr!(params::OPERATOR).to_string(),
        },
    )
}
