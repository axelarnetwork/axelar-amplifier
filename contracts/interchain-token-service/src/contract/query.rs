use axelar_wasm_std::{killswitch, IntoContractError};
use cosmwasm_std::{to_json_binary, Binary, Deps, Order};
use cw_storage_plus::Bound;
use error_stack::{Result, ResultExt};
use itertools::Itertools;
use router_api::ChainNameRaw;

use crate::{msg, state, TokenId};

// Pagination limit
const DEFAULT_LIMIT: u32 = u32::MAX;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to serialize data to JSON")]
    JsonSerialization,
    #[error("state error")]
    State,
}

pub fn its_chain(deps: Deps, chain: ChainNameRaw) -> Result<Binary, Error> {
    let state_config: Option<state::ChainConfig> =
        state::may_load_chain_config(deps.storage, &chain).change_context(Error::State)?;
    to_json_binary(&state_config.map(|config| msg::ChainConfigResponse {
        chain,
        its_edge_contract: config.its_address,
        truncation: msg::TruncationConfig {
            max_uint: config.truncation.max_uint,
            max_decimals_when_truncating: config.truncation.max_decimals_when_truncating,
        },
        frozen: config.frozen,
    }))
    .change_context(Error::JsonSerialization)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, Error> {
    let contract_addresses =
        state::load_all_its_contracts(deps.storage).change_context(Error::State)?;
    to_json_binary(&contract_addresses).change_context(Error::JsonSerialization)
}

pub fn its_chains(
    deps: Deps,
    filter: Option<msg::ChainFilter>,
    start_after: Option<ChainNameRaw>,
    limit: Option<u32>,
) -> Result<Binary, Error> {
    let state_chain_configs = state::load_chain_configs();

    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = start_after.as_ref().map(Bound::exclusive);

    let filtered_chain_configs: Vec<_> = state_chain_configs
        .range(deps.storage, start, None, Order::Ascending)
        .map(|r| r.change_context(Error::State))
        .map_ok(|(chain, config)| msg::ChainConfigResponse {
            chain,
            its_edge_contract: config.its_address,
            truncation: msg::TruncationConfig {
                max_uint: config.truncation.max_uint,
                max_decimals_when_truncating: config.truncation.max_decimals_when_truncating,
            },
            frozen: config.frozen,
        })
        .filter_ok(|config| !filter.clone().is_some_and(|f| !f.matches(config)))
        .take(limit)
        .try_collect()?;

    to_json_binary(&filtered_chain_configs).change_context(Error::JsonSerialization)
}

pub fn token_instance(deps: Deps, chain: ChainNameRaw, token_id: TokenId) -> Result<Binary, Error> {
    let token_instance = state::may_load_token_instance(deps.storage, chain, token_id)
        .change_context(Error::State)?;
    to_json_binary(&token_instance).change_context(Error::JsonSerialization)
}

pub fn token_config(deps: Deps, token_id: TokenId) -> Result<Binary, Error> {
    let token_config =
        state::may_load_token_config(deps.storage, &token_id).change_context(Error::State)?;
    to_json_binary(&token_config).change_context(Error::JsonSerialization)
}

pub fn is_contract_enabled(deps: Deps) -> Result<Binary, Error> {
    to_json_binary(&killswitch::is_contract_active(deps.storage))
        .change_context(Error::JsonSerialization)
}
