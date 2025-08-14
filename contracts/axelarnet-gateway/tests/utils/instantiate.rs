use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{message_info, mock_env};
use cosmwasm_std::{DepsMut, Response};

pub fn instantiate_contract(deps: DepsMut) -> Result<Response, ContractError> {
    contract::instantiate(
        deps,
        mock_env(),
        message_info(&router_api::SENDER_COSMOS_ADDR.clone(), &[]),
        InstantiateMsg {
            chain_name: router_api::AXELARNET_CHAIN_NAME.clone(),
            router_address: router_api::ROUTER_COSMOS_ADDR.clone().to_string(),
            nexus: router_api::NEXUS_COSMOS_ADDR.clone().to_string(),
        },
    )
}
