use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{mock_env, mock_info};
use cosmwasm_std::{DepsMut, HexBinary, Response};
use interchain_token_service::contract;
use interchain_token_service::msg::ExecuteMsg;
use router_api::{Address, ChainName, CrossChainId};

use crate::utils::params;

pub fn execute(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(params::GATEWAY, &[]),
        ExecuteMsg::Execute(axelarnet_gateway::AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }),
    )
}

pub fn set_its_address(
    deps: DepsMut,
    chain: ChainName,
    address: Address,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::SetItsAddress { chain, address },
    )
}

pub fn remove_its_address(deps: DepsMut, chain: ChainName) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(params::ADMIN, &[]),
        ExecuteMsg::RemoveItsAddress { chain },
    )
}
