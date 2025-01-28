use axelar_wasm_std::migrate_from_version;
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};

mod v1_1_1;

#[cw_serde]
pub struct MigrateMsg {
    pub chains_to_remove: Vec<String>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    v1_1_1::migrate(deps.storage, msg.chains_to_remove)?;
    Ok(Response::default())
}
