#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{killswitch, permission_control};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdResult, Storage};
use cw_storage_plus::Item;
use router_api::error::Error;

use crate::contract::CONTRACT_NAME;
use crate::state;

const BASE_VERSION: &str = "0.3.3";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    set_generalized_permission_control(storage)?;
    set_router_state(storage)?;
    Ok(())
}

#[deprecated(since = "0.3.3", note = "only used during migration")]
#[cw_serde]
struct Config {
    pub admin: Addr,
    pub governance: Addr,
    pub nexus_gateway: Addr,
}

fn set_generalized_permission_control(storage: &mut dyn Storage) -> Result<(), Error> {
    let old_config = CONFIG.load(storage)?;
    permission_control::set_admin(storage, &old_config.admin)
        .and_then(|_| permission_control::set_governance(storage, &old_config.governance))
        .map_err(Error::from)?;

    let new_config = &state::Config {
        nexus_gateway: old_config.nexus_gateway,
    };
    state::CONFIG.save(storage, new_config)?;
    Ok(())
}

fn set_router_state(storage: &mut dyn Storage) -> StdResult<()> {
    killswitch::init(storage, killswitch::State::Disengaged)
}

#[deprecated(since = "0.3.3", note = "only used during migration")]
const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::killswitch;
    use axelar_wasm_std::msg_id::MessageIdFormat;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
    use router_api::msg::ExecuteMsg;

    use crate::contract::migrations::v0_3_3;
    use crate::contract::migrations::v0_3_3::BASE_VERSION;
    use crate::contract::{execute, CONTRACT_NAME};
    use crate::events::RouterInstantiated;
    use crate::msg::InstantiateMsg;
    use crate::state;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        let _ = instantiate_0_3_3_contract(deps.as_mut()).unwrap();
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_3_3::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(v0_3_3::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn config_gets_migrated() {
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_0_3_3_contract(deps.as_mut()).unwrap();

        assert!(v0_3_3::CONFIG.load(deps.as_mut().storage).is_ok());
        assert!(state::CONFIG.load(deps.as_mut().storage).is_err());

        assert!(v0_3_3::migrate(deps.as_mut().storage).is_ok());

        assert!(v0_3_3::CONFIG.load(deps.as_mut().storage).is_err());
        let config = state::CONFIG.load(deps.as_mut().storage);
        assert!(config.is_ok());
        assert!(config.unwrap().nexus_gateway == instantiate_msg.nexus_gateway);
    }

    #[test]
    fn router_is_enabled() {
        let mut deps = mock_dependencies();
        let _ = instantiate_0_3_3_contract(deps.as_mut()).unwrap();

        assert!(v0_3_3::migrate(deps.as_mut().storage).is_ok());

        assert!(killswitch::is_contract_active(deps.as_mut().storage));
    }

    #[test]
    fn migration() {
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_0_3_3_contract(deps.as_mut()).unwrap();

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

        assert!(v0_3_3::migrate(&mut deps.storage).is_ok());

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

    fn instantiate_0_3_3_contract(deps: DepsMut) -> Result<InstantiateMsg, ContractError> {
        let admin = "admin";
        let governance = "governance";
        let nexus_gateway = "nexus_gateway";

        let msg = InstantiateMsg {
            nexus_gateway: nexus_gateway.to_string(),
            admin_address: admin.to_string(),
            governance_address: governance.to_string(),
        };
        instantiate(deps, mock_env(), mock_info(admin, &[]), msg.clone())?;
        Ok(msg)
    }

    #[deprecated(since = "0.3.3", note = "only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

        let admin = deps.api.addr_validate(&msg.admin_address)?;
        let governance = deps.api.addr_validate(&msg.governance_address)?;
        let nexus_gateway = deps.api.addr_validate(&msg.nexus_gateway)?;

        let config = v0_3_3::Config {
            admin: admin.clone(),
            governance: governance.clone(),
            nexus_gateway: nexus_gateway.clone(),
        };

        v0_3_3::CONFIG
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
