use crate::state::{CONTRACT_NAME, CONTRACT_VERSION};
use axelar_wasm_std::ContractError;
use cosmwasm_std::{Response, Storage};

pub mod v0_3_3;

pub fn set_version_after_migration(
    storage: &mut dyn Storage,
    migration: fn(&mut dyn Storage) -> Result<Response, ContractError>,
) -> Result<Response, ContractError> {
    migration(storage)?;

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
