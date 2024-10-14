use axelar_wasm_std::error::ContractError;
use cosmwasm_std::{Addr, Storage};

use crate::contract::CONTRACT_NAME;
use crate::state;

const BASE_VERSION: &str = "1.0.0";

pub fn migrate(storage: &mut dyn Storage, axelarnet_gateway: Addr) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    // migrate config
    state::save_config(storage, &state::Config { axelarnet_gateway }).map_err(Into::into)
}
#[cfg(test)]
mod test {
    #![allow(deprecated)]

    use assert_ok::assert_ok;
    use axelar_wasm_std::error::{assert_err_contains, ContractError};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
    use cw_storage_plus::Item;

    use crate::contract::migrations::v1_0_0;
    use crate::contract::migrations::v1_0_0::BASE_VERSION;
    use crate::contract::CONTRACT_NAME;
    use crate::state;

    #[deprecated(since = "1.0.0", note = "only used during migration")]
    #[cw_serde]
    pub struct InstantiateMsg {
        // admin controls freezing and unfreezing a chain
        pub admin_address: String,
        // governance votes on chains being added or upgraded
        pub governance_address: String,
        // the address of the nexus gateway
        pub nexus_gateway: String,
    }

    #[deprecated(since = "1.0.0", note = "only used during migration")]
    #[cw_serde]
    struct Config {
        pub nexus_gateway: Addr,
    }

    #[deprecated(since = "1.0.0", note = "only used during migration")]
    const CONFIG: Item<Config> = Item::new("config");

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();

        instantiate_1_0_0_contract(deps.as_mut()).unwrap();
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        let axelarnet_gateway = Addr::unchecked("axelarnet-gateway");
        assert_err_contains!(
            v1_0_0::migrate(deps.as_mut().storage, axelarnet_gateway.clone()),
            cw2::VersionError,
            cw2::VersionError::WrongVersion { .. }
        );

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();
        assert_ok!(v1_0_0::migrate(deps.as_mut().storage, axelarnet_gateway));
    }

    #[test]
    fn config_gets_migrated() {
        let mut deps = mock_dependencies();
        instantiate_1_0_0_contract(deps.as_mut()).unwrap();

        assert_ok!(CONFIG.load(deps.as_mut().storage));
        assert!(state::load_config(&deps.storage).is_err());

        let axelarnet_gateway = Addr::unchecked("axelarnet-gateway");
        assert_ok!(v1_0_0::migrate(
            deps.as_mut().storage,
            axelarnet_gateway.clone()
        ));
        assert!(CONFIG.load(deps.as_mut().storage).is_err());

        let config = assert_ok!(state::CONFIG.load(deps.as_mut().storage));
        assert_eq!(config.axelarnet_gateway, axelarnet_gateway);
    }

    fn instantiate_1_0_0_contract(deps: DepsMut) -> Result<Response, ContractError> {
        let admin = "admin";
        let governance = "governance";
        let nexus_gateway = "nexus_gateway";

        let msg = InstantiateMsg {
            admin_address: admin.to_string(),
            governance_address: governance.to_string(),
            nexus_gateway: nexus_gateway.to_string(),
        };

        instantiate(deps, mock_env(), mock_info(admin, &[]), msg.clone())
    }

    #[deprecated(since = "1.0.0", note = "only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

        let config = Config {
            nexus_gateway: deps.api.addr_validate(&msg.nexus_gateway)?,
        };

        CONFIG
            .save(deps.storage, &config)
            .expect("must save the config");

        Ok(Response::new())
    }
}
