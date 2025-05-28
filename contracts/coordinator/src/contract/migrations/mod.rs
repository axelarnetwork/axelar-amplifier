use axelar_wasm_std::{address, migrate_from_version};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;
use error_stack::ResultExt;

use crate::contract::errors::Error;
use crate::state;

#[cw_serde]
pub struct OldConfig {
    pub service_registry: Addr,
}
pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct MigrateMsg {
    pub router: String,
    pub multisig: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let old_config = OLD_CONFIG
        .load(deps.storage)
        .change_context(Error::OldConfigNotFound)?;

    let router = address::validate_cosmwasm_address(deps.api, &msg.router)?;
    let multisig = address::validate_cosmwasm_address(deps.api, &msg.multisig)?;

    OLD_CONFIG.remove(deps.storage);

    let protocol = &state::ProtocolContracts {
        service_registry: old_config.service_registry,
        router,
        multisig,
    };

    state::save_protocol_contracts(deps.storage, protocol)
        .change_context(Error::UnableToPersistProtocol)?;

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::{address, permission_control};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

    use crate::contract::migrations::{OldConfig, OLD_CONFIG};
    use crate::contract::{migrate, MigrateMsg};
    use crate::state;
    use crate::state::ProtocolContracts;

    const OLD_CONTRACT_NAME: &str = "coordinator";
    const OLD_CONTRACT_VERSION: &str = "1.1.0";

    #[cw_serde]
    pub struct OldInstantiateMsg {
        pub governance_address: String,
        pub service_registry: String,
    }

    fn old_instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: OldInstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, OLD_CONTRACT_NAME, OLD_CONTRACT_VERSION)?;

        let config = OldConfig {
            service_registry: address::validate_cosmwasm_address(deps.api, &msg.service_registry)?,
        };
        OLD_CONFIG.save(deps.storage, &config)?;

        let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
        permission_control::set_governance(deps.storage, &governance)?;

        Ok(Response::default())
    }

    #[test]
    fn migrate_sets_contract_addresses_correctly() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make("sender"), &[]);

        let service_registry = api.addr_make("service_registry");
        old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: api.addr_make("governance").to_string(),
                service_registry: service_registry.to_string(),
            },
        )
        .unwrap();

        let router = api.addr_make("router");
        let multisig = api.addr_make("multisig");
        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                router: router.to_string(),
                multisig: multisig.to_string()
            },
        )
        .is_ok());

        assert!(!OLD_CONFIG.exists(&deps.storage));

        assert_eq!(
            state::protocol_contracts(&deps.storage).ok(),
            Some(ProtocolContracts {
                service_registry,
                router,
                multisig,
            })
        )
    }
}
