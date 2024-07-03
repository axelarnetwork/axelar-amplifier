use axelar_wasm_std::{permission_control, ContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw2::VersionError;
use cw_storage_plus::Item;

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let current_version = cw2::get_contract_version(storage)?;
    if current_version.version != "0.2.0" {
        Err(VersionError::WrongVersion {
            expected: "0.2.0".into(),
            found: current_version.version,
        }
        .into())
    } else {
        migrate_config_to_permission_control(storage)?;
        Ok(())
    }
}

fn migrate_config_to_permission_control(
    storage: &mut dyn Storage,
) -> error_stack::Result<(), ContractError> {
    let config = CONFIG.load(storage).map_err(ContractError::from)?;
    permission_control::set_governance(storage, &config.governance).map_err(ContractError::from)?;
    Ok(CONFIG.remove(storage))
}

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract;
    use crate::contract::execute;
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use std::env;

    #[test]
    #[allow(deprecated)]
    fn migrate_ensure_governance_is_set() {
        let mut deps = mock_dependencies();
        env::set_var("CARGO_PKG_VERSION", "0.2.0");

        let governance = "governance";

        contract::instantiate_old(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: governance.to_string(),
            },
        )
        .unwrap();

        assert!(CONFIG.may_load(&deps.storage).unwrap().is_some());

        assert!(migrate(deps.as_mut().storage).is_ok());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("anyone", &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: "chain".parse().unwrap(),
                new_prover_addr: Addr::unchecked("any_addr"),
            },
        )
        .is_err());

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("governance", &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: "chain".parse().unwrap(),
                new_prover_addr: Addr::unchecked("any_addr"),
            },
        )
        .is_ok());

        assert!(CONFIG.may_load(&deps.storage).unwrap().is_none())
    }
}
