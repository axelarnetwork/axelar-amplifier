use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdResult, Storage};
use cw2::VersionError;
use cw_storage_plus::Item;

use axelar_wasm_std::{permission_control, ContractError};
use router_api::error::Error;

use crate::state::{Config, State, CONFIG, STATE};

const BASE_VERSION: &str = "0.3.3";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let current_version = cw2::get_contract_version(storage)?;
    if current_version.version != BASE_VERSION {
        Err(VersionError::WrongVersion {
            expected: BASE_VERSION.into(),
            found: current_version.version,
        })?
    } else {
        set_generalized_permission_control(storage)?;
        set_router_state(storage)?;
        Ok(())
    }
}

#[deprecated(since = "0.3.3", note = "only used during migration")]
#[cw_serde]
struct ConfigOld {
    pub admin: Addr,
    pub governance: Addr,
    pub nexus_gateway: Addr,
}

#[allow(deprecated)]
fn set_generalized_permission_control(storage: &mut dyn Storage) -> Result<(), Error> {
    let old_config = CONFIG_OLD.load(storage)?;
    permission_control::set_admin(storage, &old_config.admin)
        .and_then(|_| permission_control::set_governance(storage, &old_config.governance))
        .map_err(Error::from)?;

    let new_config = &Config {
        nexus_gateway: old_config.nexus_gateway,
    };
    CONFIG.save(storage, new_config)?;
    Ok(())
}

fn set_router_state(storage: &mut dyn Storage) -> StdResult<()> {
    STATE.save(storage, &State::Enabled)
}

#[deprecated(since = "0.3.3", note = "only used during migration")]
#[allow(deprecated)]
const CONFIG_OLD: Item<ConfigOld> = Item::new("config");

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use std::collections::HashMap;
    use std::env;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

    use axelar_wasm_std::msg_id::MessageIdFormat;
    use axelar_wasm_std::ContractError;
    use router_api::msg::ExecuteMsg;

    use crate::contract::execute;
    use crate::events::RouterInstantiated;
    use crate::msg::InstantiateMsg;
    use crate::state::{State, CONFIG, CONTRACT_NAME, CONTRACT_VERSION, STATE};

    use super::{migrate, ConfigOld, BASE_VERSION, CONFIG_OLD};

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        let _ = instantiate_old_contract(deps.as_mut()).unwrap();
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn config_gets_migrated() {
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_old_contract(deps.as_mut()).unwrap();

        assert!(CONFIG_OLD.load(deps.as_mut().storage).is_ok());
        assert!(CONFIG.load(deps.as_mut().storage).is_err());

        assert!(migrate(deps.as_mut().storage).is_ok());

        assert!(CONFIG_OLD.load(deps.as_mut().storage).is_err());
        let config = CONFIG.load(deps.as_mut().storage);
        assert!(config.is_ok());
        assert!(config.unwrap().nexus_gateway == instantiate_msg.nexus_gateway);
    }

    #[test]
    fn set_router_state() {
        let mut deps = mock_dependencies();
        let _ = instantiate_old_contract(deps.as_mut()).unwrap();

        assert!(migrate(deps.as_mut().storage).is_ok());

        let state = STATE.load(deps.as_ref().storage);
        assert!(state.is_ok());
        assert_eq!(state.unwrap(), State::Enabled);
    }

    #[test]
    #[allow(deprecated)]
    fn migration() {
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_old_contract(deps.as_mut()).unwrap();

        let msg = ExecuteMsg::RegisterChain {
            chain: "chain".parse().unwrap(),
            gateway_address: "gateway".parse().unwrap(),
            msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
        };

        // before migration no address should be able to execute this message

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&instantiate_msg.admin_address, &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&instantiate_msg.governance_address, &[]),
            msg.clone(),
        )
        .is_err());

        //set to future version
        env::set_var("CARGO_PKG_VERSION", "0.4.0");
        assert!(migrate(&mut deps.storage).is_ok());

        // after migration only governance should be able to register a chain
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&instantiate_msg.admin_address, &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&instantiate_msg.governance_address, &[]),
            msg.clone(),
        )
        .is_ok());

        // check that both admin and governance permissions are set correctly

        let msg = ExecuteMsg::UnfreezeChains {
            chains: HashMap::new(),
        };

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("no_privilege", &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(instantiate_msg.admin_address.as_str(), &[]),
            msg.clone(),
        )
        .is_ok());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(instantiate_msg.governance_address.as_str(), &[]),
            msg.clone(),
        )
        .is_ok());
    }

    #[allow(deprecated)]
    fn instantiate_old_contract(deps: DepsMut) -> Result<InstantiateMsg, ContractError> {
        let admin = "admin";
        let governance = "governance";
        let nexus_gateway = "nexus_gateway";

        let msg = InstantiateMsg {
            nexus_gateway: nexus_gateway.to_string(),
            admin_address: admin.to_string(),
            governance_address: governance.to_string(),
        };
        instantiate_old(deps, mock_env(), mock_info(admin, &[]), msg.clone())?;
        Ok(msg)
    }

    #[deprecated(since = "0.3.3", note = "only used to test the migration")]
    #[allow(deprecated)]
    pub fn instantiate_old(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        let admin = deps.api.addr_validate(&msg.admin_address)?;
        let governance = deps.api.addr_validate(&msg.governance_address)?;
        let nexus_gateway = deps.api.addr_validate(&msg.nexus_gateway)?;

        let config = ConfigOld {
            admin: admin.clone(),
            governance: governance.clone(),
            nexus_gateway: nexus_gateway.clone(),
        };

        CONFIG_OLD
            .save(deps.storage, &config)
            .expect("must save the config");

        Ok(Response::new().add_event(
            RouterInstantiated {
                admin,
                governance,
                nexus_gateway,
            }
            .into(),
        ))
    }
}
