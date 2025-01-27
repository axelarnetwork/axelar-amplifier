use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{from_json, Deps};
use interchain_token_service::contract::query;
use interchain_token_service::msg::{ChainConfig, QueryMsg};
use interchain_token_service::{TokenConfig, TokenId, TokenInstance};
use router_api::{Address, ChainNameRaw};

pub fn query_chain_config(
    deps: Deps,
    chain: ChainNameRaw,
) -> Result<Option<ChainConfig>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::ChainConfig { chain })?;
    Ok(from_json(bin)?)
}

pub fn query_all_its_contracts(
    deps: Deps,
) -> Result<HashMap<ChainNameRaw, Address>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::AllItsContracts)?;
    Ok(from_json(bin)?)
}

pub fn query_token_instance(
    deps: Deps,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<Option<TokenInstance>, ContractError> {
    let bin = query(
        deps,
        mock_env(),
        QueryMsg::TokenInstance { chain, token_id },
    )?;
    Ok(from_json(bin)?)
}

pub fn query_token_config(
    deps: Deps,
    token_id: TokenId,
) -> Result<Option<TokenConfig>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::TokenConfig { token_id })?;
    Ok(from_json(bin)?)
}

pub fn assert_chain_configs_match(original: &ChainConfig, queried: &ChainConfig) {
    assert_eq!(
        original.chain, queried.chain,
        "Chain name mismatch. Expected: {:?}, Got: {:?}",
        original.chain, queried.chain
    );
    assert_eq!(
        original.its_edge_contract, queried.its_edge_contract,
        "ITS edge contract mismatch. Expected: {:?}, Got: {:?}",
        original.its_edge_contract, queried.its_edge_contract
    );
    assert_eq!(
        original.truncation.max_uint, queried.truncation.max_uint,
        "Max uint mismatch. Expected: {:?}, Got: {:?}",
        original.truncation.max_uint, queried.truncation.max_uint
    );
    assert_eq!(
        original.truncation.max_decimals_when_truncating,
        queried.truncation.max_decimals_when_truncating,
        "Max decimals mismatch. Expected: {:?}, Got: {:?}",
        original.truncation.max_decimals_when_truncating,
        queried.truncation.max_decimals_when_truncating
    );
}
