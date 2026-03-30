use axelar_wasm_std::{address, migrate_from_version};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};

use crate::state::CONFIG;

#[cw_serde]
pub struct MigrateMsg {
    /// Optional new address for the chain codec contract
    pub chain_codec_address: Option<String>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    if let Some(chain_codec_address) = msg.chain_codec_address {
        let chain_codec = address::validate_cosmwasm_address(deps.api, &chain_codec_address)?;

        CONFIG.update(deps.storage, |mut config| -> Result<_, axelar_wasm_std::error::ContractError> {
            config.chain_codec = chain_codec;
            Ok(config)
        })?;
    }

    Ok(Response::default())
}
