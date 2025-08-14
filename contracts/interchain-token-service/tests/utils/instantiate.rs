use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{message_info, mock_env};
use cosmwasm_std::{DepsMut, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        message_info(&router_api::SENDER_COSMOS_ADDR.clone(), &[]),
        InstantiateMsg {
            governance_address: router_api::GOVERNANCE_COSMOS_ADDR.clone().to_string(),
            admin_address: router_api::ADMIN_COSMOS_ADDR.clone().to_string(),
            axelarnet_gateway_address: router_api::GATEWAY_COSMOS_ADDR.clone().to_string(),
            operator_address: router_api::OPERATOR_COSMOS_ADDR.clone().to_string(),
        },
    )
}
