#![allow(deprecated)]

use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, StdError, Storage};
use cw2::VersionError;

use crate::contract::CONTRACT_NAME;

const BASE_VERSION: &str = "1.0.0";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Version(#[from] VersionError),
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
}

pub fn migrate(storage: &mut dyn Storage, service_registry: Addr) -> Result<(), Error> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    migrate_config(storage, service_registry)?;
    Ok(())
}

fn migrate_config(storage: &mut dyn Storage, service_registry: Addr) -> Result<(), Error> {
    let new_config = crate::state::Config { service_registry };
    crate::state::CONFIG.save(storage, &new_config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{address, permission_control};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};

    use crate::contract::migrations::v1_0_0::{self, BASE_VERSION};
    use crate::contract::CONTRACT_NAME;

    const GOVERNANCE: &str = "governance";

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage, Addr::unchecked("random_service")).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage, Addr::unchecked("random_service")).is_ok());
    }

    #[test]
    fn migrate_config() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
            },
        )
        .unwrap();

        let service_registry_address = Addr::unchecked("random_service");
        assert!(v1_0_0::migrate(deps.as_mut().storage, service_registry_address.clone()).is_ok());

        let config_result = crate::state::CONFIG.load(deps.as_mut().storage);
        assert!(config_result.is_ok());

        let config = config_result.unwrap();
        assert_eq!(config.service_registry, service_registry_address)
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: GOVERNANCE.to_string(),
            },
        )
        .unwrap();
    }

    #[deprecated(since = "1.0.0", note = "only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

        let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
        permission_control::set_governance(deps.storage, &governance)?;

        Ok(Response::default())
    }

    #[cw_serde]
    #[deprecated(since = "1.0.0", note = "only used to test the migration")]
    struct InstantiateMsg {
        pub governance_address: String,
    }
}
