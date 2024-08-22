#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use cosmwasm_std::Storage;

use crate::contract::CONTRACT_NAME;

const BASE_VERSION: &str = "0.4.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let current_version = cw2::get_contract_version(storage)?;

    if current_version.version != "1.0.0" {
        cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;

    use crate::contract::migrations::v0_4_0;
    use crate::contract::migrations::v0_4_0::BASE_VERSION;
    use crate::contract::CONTRACT_NAME;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_4_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(v0_4_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_from_v1_updates_version() {
        let mut deps = mock_dependencies();

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "1.0.0").unwrap();

        assert!(v0_4_0::migrate(deps.as_mut().storage).is_ok());
    }
}
