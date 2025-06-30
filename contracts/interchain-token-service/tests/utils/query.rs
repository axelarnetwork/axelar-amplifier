use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{from_json, Deps};
use interchain_token::TokenId;
use interchain_token_service::contract::query;
use interchain_token_service::msg;
use interchain_token_service::msg::{ChainConfigResponse, ChainFilter, QueryMsg, TruncationConfig};
use interchain_token_service::shared::NumBits;
use router_api::{Address, ChainNameRaw};

pub fn query_its_chain(
    deps: Deps,
    chain: ChainNameRaw,
) -> Result<Option<ChainConfigResponse>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::ItsChain { chain })?;
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
) -> Result<Option<msg::TokenInstance>, ContractError> {
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
) -> Result<Option<msg::TokenConfig>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::TokenConfig { token_id })?;
    Ok(from_json(bin)?)
}

pub fn query_is_contract_enabled(deps: Deps) -> Result<bool, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::IsEnabled {})?;
    Ok(from_json(bin)?)
}

pub fn query_its_chains(
    deps: Deps,
    filter: Option<ChainFilter>,
    start_after: Option<ChainNameRaw>,
    limit: u32,
) -> Result<Vec<ChainConfigResponse>, ContractError> {
    let bin = query(
        deps,
        mock_env(),
        QueryMsg::ItsChains {
            filter,
            start_after,
            limit,
        },
    )?;
    Ok(from_json(bin)?)
}

pub struct ChainData {
    pub chain: ChainNameRaw,
    pub address: Address,
    pub max_uint_bits: NumBits,
    pub max_decimals: u8,
}

pub fn create_config_response(chain_data: &ChainData, frozen: bool) -> ChainConfigResponse {
    ChainConfigResponse {
        chain: chain_data.chain.clone(),
        its_edge_contract: chain_data.address.clone(),
        truncation: TruncationConfig {
            max_uint_bits: chain_data.max_uint_bits,
            max_decimals_when_truncating: chain_data.max_decimals,
        },
        frozen,
        translation_contract: cosmwasm_std::testing::MockApi::default()
            .addr_make("translation_contract"),
    }
}

pub fn assert_configs_equal(actual: &[ChainConfigResponse], expected: &[ChainConfigResponse]) {
    assert_eq!(actual.len(), expected.len(), "Different number of configs");
    for (a, e) in actual.iter().zip(expected.iter()) {
        assert_eq!(a, e, "Config mismatch for chain {}", e.chain);
    }
}
