#![allow(deprecated)]

use axelar_wasm_std::address;
use axelar_wasm_std::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Storage};
use cw_storage_plus::Item;

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
use crate::msg::MigrateMsg;
use crate::state;

const BASE_VERSION: &str = "1.0.0";
const CONFIG: Item<Config> = Item::new("config");

pub fn migrate(deps: DepsMut, msg: MigrateMsg) -> Result<(), ContractError> {
    cw2::assert_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

    let axelarnet_gateway = address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway)?;
    migrate_config(deps.storage, axelarnet_gateway)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(())
}

fn migrate_config(storage: &mut dyn Storage, axelarnet_gateway: Addr) -> Result<(), ContractError> {
    let config = CONFIG.load(storage)?;

    state::save_config(
        storage,
        state::Config {
            nexus: config.nexus,
            router: config.router,
            axelarnet_gateway,
        },
    )
    .map_err(Into::into)
}

#[cw_serde]
#[deprecated(since = "1.0.0", note = "only used during migration")]
pub struct Config {
    pub nexus: Addr,
    pub router: Addr,
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, DepsMut};
    use cw2::ContractVersion;

    use super::{Config, BASE_VERSION, CONFIG};
    use crate::contract::migrations::v1_0_0;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use crate::msg::MigrateMsg;
    use crate::state;

    const NEXUS: &str = "nexus";
    const ROUTER: &str = "router";
    const AXELARNET_GATEWAY: &str = "cosmwasm16en9ateq5565c4n26ed0wykmnqhd0thp5eatgc";

    #[test]
    fn migrate_should_error_if_current_contract_version_is_not_correct() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v1_0_0::migrate(
            deps.as_mut(),
            MigrateMsg {
                axelarnet_gateway: AXELARNET_GATEWAY.to_string(),
            }
        )
        .is_err());
    }

    #[test]
    fn migrate_should_migrate_the_config_and_set_correct_version_number() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(CONFIG.load(&deps.storage).is_ok());
        assert!(state::load_config(&deps.storage).is_err());
        assert_eq!(
            cw2::get_contract_version(&deps.storage).unwrap(),
            ContractVersion {
                contract: CONTRACT_NAME.to_string(),
                version: BASE_VERSION.to_string()
            }
        );

        assert!(v1_0_0::migrate(
            deps.as_mut(),
            MigrateMsg {
                axelarnet_gateway: AXELARNET_GATEWAY.to_string(),
            }
        )
        .is_ok());

        assert!(CONFIG.load(&deps.storage).is_err());
        assert!(state::load_config(&deps.storage)
            .is_ok_and(|config| config.axelarnet_gateway == Addr::unchecked(AXELARNET_GATEWAY)));
        assert_eq!(
            cw2::get_contract_version(&deps.storage).unwrap(),
            ContractVersion {
                contract: CONTRACT_NAME.to_string(),
                version: CONTRACT_VERSION.to_string()
            }
        );
    }

    fn instantiate_contract(deps: DepsMut) {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        CONFIG
            .save(
                deps.storage,
                &Config {
                    nexus: Addr::unchecked(NEXUS),
                    router: Addr::unchecked(ROUTER),
                },
            )
            .unwrap();
    }
}
