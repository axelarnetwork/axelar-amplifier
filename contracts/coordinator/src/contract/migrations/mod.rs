use axelar_wasm_std::{migrate_from_version, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;
use error_stack::ResultExt;

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
use crate::state::{Config, CONFIG};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("coordinator migration failed")]
    Migration,
}

#[cw_serde]
pub struct OldConfig {
    pub service_registry: Addr,
}
pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct MigrateMsg {
    pub router: Addr,
    pub multisig: Addr,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::ensure_from_older_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)
        .change_context(Error::Migration)?;

    let old_config = OLD_CONFIG.load(deps.storage)?;

    CONFIG.save(
        deps.storage,
        &Config {
            service_registry: old_config.service_registry,
            router: msg.router,
            multisig: msg.multisig,
        },
    )?;

    Ok(Response::default())
}
