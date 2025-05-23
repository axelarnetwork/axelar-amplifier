use axelar_wasm_std::{address, migrate_from_version};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct OldConfig {
    pub axelarnet_gateway: Addr,
}
pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let old_config = OLD_CONFIG.load(deps.storage)?;

    let coordinator = address::validate_cosmwasm_address(deps.api, msg.coordinator.as_str())?;

    CONFIG.save(
        deps.storage,
        &Config {
            axelarnet_gateway: old_config.axelarnet_gateway,
            coordinator,
        },
    )?;

    Ok(Response::default())
}
