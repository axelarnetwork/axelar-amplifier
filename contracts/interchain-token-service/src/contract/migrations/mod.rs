use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::migrate_from_version;
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};

pub mod v1_1_0;

#[cw_serde]
pub struct MigrateMsg {
    operator_address: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    v1_1_0::migrate(deps, msg)?;
    Ok(Response::default())
}
