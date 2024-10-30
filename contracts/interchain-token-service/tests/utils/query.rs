use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{from_json, Deps};
use interchain_token_service::contract::query;
use interchain_token_service::msg::QueryMsg;
use interchain_token_service::{TokenChainConfig, TokenId};
use router_api::{Address, ChainNameRaw};

pub fn query_its_contract(
    deps: Deps,
    chain: ChainNameRaw,
) -> Result<Option<Address>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::ItsContract { chain })?;
    Ok(from_json(bin)?)
}

pub fn query_all_its_contracts(
    deps: Deps,
) -> Result<HashMap<ChainNameRaw, Address>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::AllItsContracts)?;
    Ok(from_json(bin)?)
}

pub fn query_token_chain_config(
    deps: Deps,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<Option<TokenChainConfig>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::TokenChainConfig { chain, token_id })?;
    Ok(from_json(bin)?)
}
