use axelar_wasm_std::address::{validate_cosmwasm_address, AddressFormat};
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{migrate_from_version, nonempty, MajorityThreshold};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;
use router_api::ChainName;

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct MigrateMsg {
    /// Address to the chain codec contract to use for this migration
    pub chain_codec_address: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("2.0")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let chain_codec_address = validate_cosmwasm_address(deps.api, &msg.chain_codec_address)?;

    let old_config = OLD_CONFIG.load(deps.storage)?;

    // query chain codec with source gateway address as a sanity check
    // if it fails, the chain codec contract is incorrect
    let chain_codec: chain_codec_api::Client =
        client::ContractClient::new(deps.querier, &chain_codec_address).into();
    chain_codec.validate_address(old_config.source_gateway_address.to_string())?;

    CONFIG.save(
        deps.storage,
        &Config {
            service_registry_contract: old_config.service_registry_contract,
            service_name: old_config.service_name,
            source_gateway_address: old_config.source_gateway_address,
            voting_threshold: old_config.voting_threshold,
            block_expiry: old_config.block_expiry,
            confirmation_height: old_config.confirmation_height,
            source_chain: old_config.source_chain,
            rewards_contract: old_config.rewards_contract,
            msg_id_format: old_config.msg_id_format,
            chain_codec_address,
        },
    )?;
    Ok(Response::default())
}

pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");
#[cw_serde]
pub struct OldConfig {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
    pub msg_id_format: MessageIdFormat,
    pub address_format: AddressFormat,
}
