use axelar_wasm_std::migrate_from_version;
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};

#[cw_serde]
pub struct MigrateMsg {
    /// Address to the chain codec contract to use for this migration
    pub chain_codec_address: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("0.4")]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    Ok(Response::default())
}
