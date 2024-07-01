use crate::state::{State, CONFIG, STATE};
use axelar_wasm_std::{permission_control, ContractError};
use cosmwasm_std::{StdResult, Storage};
use cw2::VersionError;

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let current_version = cw2::get_contract_version(storage)?;
    if current_version.version != "0.3.3" {
        Err(VersionError::WrongVersion {
            expected: "0.3.3".into(),
            found: current_version.version,
        }
        .into())
    } else {
        set_generalized_permission_control(storage)?;
        set_router_state(storage)?;
        Ok(())
    }
}

fn set_router_state(storage: &mut dyn Storage) -> StdResult<()> {
    STATE.save(storage, &State::Enabled)
}

fn set_generalized_permission_control(storage: &mut dyn Storage) -> StdResult<()> {
    let config = CONFIG.load(storage)?;
    permission_control::set_admin(storage, &config.admin)?;
    permission_control::set_governance(storage, &config.governance)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::state::Config;
    use crate::state::{State, CONFIG, STATE};
    use axelar_wasm_std::ensure_permission;
    use axelar_wasm_std::permission_control::{Error, Permission};
    use cosmwasm_std::testing::MockStorage;
    use cosmwasm_std::{Addr, Storage};
    use error_stack::Report;

    #[test]
    fn set_router_state() {
        let mut storage = MockStorage::new();

        assert!(STATE.load(&storage).is_err());

        super::set_router_state(&mut storage).unwrap();

        let state = STATE.load(&storage).unwrap();
        assert_eq!(state, State::Enabled);
    }

    #[test]
    fn set_generalized_permission_control() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };

        let mut storage = MockStorage::new();
        CONFIG.save(&mut storage, &config).unwrap();

        let check_admin = |storage: &mut dyn Storage| {
            ensure_permission!(Permission::Admin, storage, &config.admin);
            Ok::<(), Report<Error>>(())
        };

        let check_governance = |storage: &mut dyn Storage| {
            ensure_permission!(Permission::Governance, storage, &config.governance);
            Ok::<(), Report<Error>>(())
        };
        assert!(check_admin(&mut storage).is_err());
        assert!(check_governance(&mut storage).is_err());

        super::set_generalized_permission_control(&mut storage).unwrap();

        assert!(check_admin(&mut storage).is_ok());
        assert!(check_governance(&mut storage).is_ok());
    }
}
