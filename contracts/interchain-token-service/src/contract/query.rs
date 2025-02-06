use axelar_wasm_std::{killswitch, IntoContractError};
use cosmwasm_std::{to_json_binary, Binary, Deps};
use error_stack::{Result, ResultExt};
use router_api::ChainNameRaw;

use crate::{msg, state, TokenId};

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

pub fn its_chains(deps: Deps, filter: Option<msg::ChainFilter>) -> Result<Binary, Error> {
    let state_configs = state::load_chain_configs(deps.storage).change_context(Error::State)?;

    let chain_configs = match filter {
        Some(filter) if filter.frozen_status.is_some() => state_configs
            .into_iter()
            .filter(|config| matches_filter(config, filter.frozen_status.as_ref()))
            .collect(),
        _ => state_configs,
    };
    to_json_binary(&chain_configs).change_context(Error::JsonSerialization)
}

fn matches_filter(
    config: &msg::ChainConfigResponse,
    status: Option<&msg::ChainStatusFilter>,
) -> bool {
    match status {
        Some(msg::ChainStatusFilter::Frozen) => config.frozen,
        Some(msg::ChainStatusFilter::Active) => !config.frozen,
        None => true,
    }
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
