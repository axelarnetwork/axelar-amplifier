use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{message_info, mock_env, MockApi};
use cosmwasm_std::{DepsMut, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;
use router_api::cosmos_addr;

use crate::utils::params;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    let api = MockApi::default();

    contract::instantiate(
        deps,
        mock_env(),
        message_info(&cosmos_addr!("sender"), &[]),
        InstantiateMsg {
            governance_address: api.addr_make(params::GOVERNANCE).to_string(),
            admin_address: api.addr_make(params::ADMIN).to_string(),
            axelarnet_gateway_address: api.addr_make(params::GATEWAY).to_string(),
            operator_address: api.addr_make(params::OPERATOR).to_string(),
        },
    )
}
