use std::usize;

use axelar_wasm_std::{migrate_from_version, nonempty::Usize, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Empty, Env, Response};
use error_stack::ResultExt;
use service_registry_api::{error::ContractError};
use crate::state::{services, update_authorized_verifier_count};

pub type MigrateMsg = Empty;

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
enum MigrationError {
    #[error("invalid limit")]
    InvalidLimit,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let services = services(deps.storage, None, Usize::try_from(usize::MAX)
        .change_context(MigrationError::InvalidLimit)?)
        .change_context(ContractError::ServiceNotFound)?;

    for s in services {
        update_authorized_verifier_count(deps.storage, &s.name)?;
    }
    
    Ok(Response::default())
}
