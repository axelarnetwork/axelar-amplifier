//! Migrations for the Coordinator contract.
//!
//! To make it easier to manage the migrations, we put the actual implementation into submodules.
//! This way, multiple migrations can be combined and switched out more easily, when we release a new version.

use crate::error::ContractError;
use crate::state::{CONTRACT_NAME, CONTRACT_VERSION};
use cosmwasm_std::{Response, Storage};

pub mod v0_2_0;

pub fn set_version_after_migration(
    storage: &mut dyn Storage,
    migration: fn(&mut dyn Storage) -> Result<Response, ContractError>,
) -> Result<Response, ContractError> {
    migration(storage)?;

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use crate::contract::migrations::set_version_after_migration;
    use crate::state::{CONTRACT_NAME, CONTRACT_VERSION};
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Response, StdError};

    #[test]
    #[allow(deprecated)]
    fn set_contract_version_only_on_migration_success() {
        let mut deps = mock_dependencies();

        cw2::set_contract_version(deps.as_mut().storage, "contract", "old").unwrap();

        assert!(set_version_after_migration(deps.as_mut().storage, |_| Err(
            StdError::generic_err("some_error").into()
        ))
        .is_err());

        let version = cw2::get_contract_version(deps.as_ref().storage).unwrap();
        assert!(version.contract == "contract");
        assert!(version.version == "old");

        assert!(
            set_version_after_migration(deps.as_mut().storage, |_| Ok(Response::default())).is_ok()
        );

        let version = cw2::get_contract_version(deps.as_ref().storage).unwrap();
        assert!(version.contract == CONTRACT_NAME);
        assert!(version.version == CONTRACT_VERSION);
    }
}
