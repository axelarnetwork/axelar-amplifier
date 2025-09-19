use axelar_wasm_std::{killswitch, nonempty, IntoContractError};
use cosmwasm_std::{to_json_binary, Binary, Deps};
use error_stack::{Result, ResultExt};
use interchain_token_service_std::TokenId;
use itertools::Itertools;
use router_api::ChainNameRaw;

use crate::{msg, state};

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
            max_uint_bits: config.truncation.max_uint_bits,
            max_decimals_when_truncating: config.truncation.max_decimals_when_truncating,
        },
        frozen: config.frozen,
        msg_translator: config.msg_translator,
    }))
    .change_context(Error::JsonSerialization)
}

pub fn all_its_contracts(deps: Deps) -> Result<Binary, Error> {
    let contract_addresses =
        state::load_all_its_contracts(deps.storage).change_context(Error::State)?;
    to_json_binary(&contract_addresses).change_context(Error::JsonSerialization)
}

fn convert_chain_filter(chain_filter: msg::ChainFilter) -> impl Fn(&state::ChainConfig) -> bool {
    move |config| match &chain_filter.status {
        Some(msg::ChainStatusFilter::Frozen) => config.frozen,
        Some(msg::ChainStatusFilter::Active) => !config.frozen,
        None => true,
    }
}

pub fn its_chains(
    deps: Deps,
    filter: Option<msg::ChainFilter>,
    start_after: Option<ChainNameRaw>,
    limit: u32,
) -> Result<Binary, Error> {
    let filtered_chain_configs: Vec<_> = state::load_chain_configs(
        deps.storage,
        convert_chain_filter(filter.unwrap_or_default()),
        start_after,
        limit,
    )
    .map(|r| r.change_context(Error::State))
    .map_ok(|(chain, config)| msg::ChainConfigResponse {
        chain,
        its_edge_contract: config.its_address,
        truncation: msg::TruncationConfig {
            max_uint_bits: config.truncation.max_uint_bits,
            max_decimals_when_truncating: config.truncation.max_decimals_when_truncating,
        },
        frozen: config.frozen,
        msg_translator: config.msg_translator,
    })
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

pub fn custom_token_metadata(
    deps: Deps,
    chain: ChainNameRaw,
    token_address: nonempty::HexBinary,
) -> Result<Binary, Error> {
    let custom_token = state::may_load_custom_token(deps.storage, chain, token_address)
        .change_context(Error::State)?
        .map(|token| msg::CustomTokenMetadata {
            decimals: token.decimals,
        });
    to_json_binary(&custom_token).change_context(Error::JsonSerialization)
}

pub fn is_contract_enabled(deps: Deps) -> Result<Binary, Error> {
    to_json_binary(&killswitch::is_contract_active(deps.storage))
        .change_context(Error::JsonSerialization)
}
