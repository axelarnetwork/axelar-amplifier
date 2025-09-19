use axelar_wasm_std::address::validate_cosmwasm_address;
use axelar_wasm_std::{hash::Hash, migrate_from_version, MajorityThreshold};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;
use multisig::key::KeyType;
use router_api::ChainName;

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct MigrateMsg {
    /// Address to the chain codec contract to use for this migration
    pub chain_codec_address: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let chain_codec_address = validate_cosmwasm_address(deps.api, &msg.chain_codec_address)?;

    let old_config = OLD_CONFIG.load(deps.storage)?;

    CONFIG.save(
        deps.storage,
        &Config {
            gateway: old_config.gateway,
            multisig: old_config.multisig,
            coordinator: old_config.coordinator,
            service_registry: old_config.service_registry,
            voting_verifier: old_config.voting_verifier,
            signing_threshold: old_config.signing_threshold,
            service_name: old_config.service_name,
            chain_name: old_config.chain_name,
            verifier_set_diff_threshold: old_config.verifier_set_diff_threshold,
            key_type: old_config.key_type,
            domain_separator: old_config.domain_separator,
            chain_codec: chain_codec_address,

            // existing deployments with our own multisig-prover contract don't need to receive full message payloads, so we don't enable it here
            expect_full_message_payloads: false,
            // existing deployments with our own multisig-prover contract don't use notify signing session, so we don't enable it here
            // we might have to enable it if we migrate other multisig-prover forks in the future
            notify_signing_session: false,
            // existing deployments couldn't use a custom signature verifier, so we don't have to specify one here
            sig_verifier_address: None,
        },
    )?;
    Ok(Response::default())
}

pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct OldConfig {
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    // we are dropping this with the migration anyway and the type does not exist anymore,
    // so we just comment it out
    // pub encoder: Encoder,
    pub domain_separator: Hash,
    pub key_type: KeyType,
}
