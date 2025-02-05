use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{from_json, Deps};
use interchain_token_service::contract::query;
use interchain_token_service::msg::{
    ChainConfigFilter, ChainConfigResponse, QueryMsg, TruncationConfig,
};
use interchain_token_service::{TokenConfig, TokenId, TokenInstance};
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

pub fn query_is_contract_enabled(deps: Deps) -> Result<bool, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::IsEnabled {})?;
    Ok(from_json(bin)?)
}

pub fn query_its_chains(
    deps: Deps,
    filter: Option<ChainConfigFilter>,
) -> Result<Vec<ChainConfigResponse>, ContractError> {
    let bin = query(deps, mock_env(), QueryMsg::ItsChains { filter })?;
    Ok(from_json(bin)?)
}

pub fn create_expected_chain_config(
    chain: ChainNameRaw,
    address: Address,
    max_uint: nonempty::Uint256,
    max_decimals: u8,
    frozen: bool,
) -> ChainConfigResponse {
    ChainConfigResponse {
        chain,
        its_edge_contract: address,
        truncation: TruncationConfig {
            max_uint,
            max_decimals_when_truncating: max_decimals,
        },
        frozen,
    }
}
