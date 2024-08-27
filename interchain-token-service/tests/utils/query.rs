use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{from_json, Deps};
use interchain_token_service::contract::query;
use interchain_token_service::msg::QueryMsg;
use router_api::{Address, ChainName};

pub fn query_its_address(deps: Deps, chain: ChainName) -> Result<Option<Address>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::ItsAddress { chain })?;
    Ok(from_json(bin)?)
}

pub fn query_all_its_addresses(deps: Deps) -> Result<HashMap<ChainName, Address>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::AllItsAddresses)?;
    Ok(from_json(bin)?)
}
