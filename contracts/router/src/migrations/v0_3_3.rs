use cosmwasm_std::{StdResult, Storage};
use cw2::VersionError;

use axelar_wasm_std::{permission_control, ContractError};

use crate::state::CONFIG;

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
        Ok(())
    }
}

fn set_generalized_permission_control(storage: &mut dyn Storage) -> StdResult<()> {
    let config = CONFIG.load(storage)?;
    permission_control::set_admin(storage, &config.admin)?;
    permission_control::set_governance(storage, &config.governance)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::MockStorage;
    use cosmwasm_std::Addr;

    use router_api::msg::ExecuteMsg;
    use router_api::GatewayDirection;

    use crate::state::Config;
    use crate::state::CONFIG;

    #[test]
    fn set_generalized_permission_control() {
        let config = Config {
            admin: Addr::unchecked("admin"),
            governance: Addr::unchecked("governance"),
            nexus_gateway: Addr::unchecked("nexus_gateway"),
        };

        let mut storage = MockStorage::new();
        CONFIG.save(&mut storage, &config).unwrap();

        let msg = ExecuteMsg::UnfreezeChain {
            chain: "chain".parse().unwrap(),
            direction: GatewayDirection::Bidirectional,
        };
        assert!(msg
            .clone()
            .ensure_permission(&mut storage, &config.admin)
            .is_err());
        assert!(msg
            .clone()
            .ensure_permission(&mut storage, &config.governance)
            .is_err());

        super::set_generalized_permission_control(&mut storage).unwrap();

        assert!(msg
            .clone()
            .ensure_permission(&mut storage, &config.admin)
            .is_ok());

        assert!(msg
            .clone()
            .ensure_permission(&mut storage, &config.governance)
            .is_ok());
    }
}
