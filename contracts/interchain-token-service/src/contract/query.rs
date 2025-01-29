use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{to_json_binary, Binary, Deps};
use error_stack::{Result, ResultExt};
use router_api::ChainNameRaw;

use crate::msg::{ChainConfigResponse, TruncationConfig as MsgTruncationConfig};
use crate::state::{
    load_all_its_contracts, may_load_chain_config, may_load_token_config, may_load_token_instance,
    ChainConfig as StateChainConfig,
};
use crate::TokenId;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to serialize data to JSON")]
    JsonSerialization,
    #[error("state error")]
    State,
}

pub fn chain_config(deps: Deps, chain: ChainNameRaw) -> Result<Binary, Error> {
    let state_config: Option<StateChainConfig> =
        may_load_chain_config(deps.storage, &chain).change_context(Error::State)?;
    to_json_binary(&state_config.map(|config| ChainConfigResponse {
        chain,
        its_edge_contract: config.its_address,
        truncation: MsgTruncationConfig {
            max_uint: config.truncation.max_uint,
            max_decimals_when_truncating: config.truncation.max_decimals_when_truncating,
        },
        frozen: config.frozen,
    }))
    .change_context(Error::JsonSerialization)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, Error> {
    let contract_addresses = load_all_its_contracts(deps.storage).change_context(Error::State)?;
    to_json_binary(&contract_addresses).change_context(Error::JsonSerialization)
}

pub fn token_instance(deps: Deps, chain: ChainNameRaw, token_id: TokenId) -> Result<Binary, Error> {
    let token_instance =
        may_load_token_instance(deps.storage, chain, token_id).change_context(Error::State)?;
    to_json_binary(&token_instance).change_context(Error::JsonSerialization)
}

pub fn token_config(deps: Deps, token_id: TokenId) -> Result<Binary, Error> {
    let token_config =
        may_load_token_config(deps.storage, &token_id).change_context(Error::State)?;
    to_json_binary(&token_config).change_context(Error::JsonSerialization)
}
