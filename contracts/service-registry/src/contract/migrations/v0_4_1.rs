#![allow(deprecated)]
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdResult, Storage};
use cw_storage_plus::Item;

use crate::contract::CONTRACT_NAME;

const BASE_VERSION: &str = "0.4.1";
pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    let config = CONFIG.load(storage)?;
    delete_config(storage);
    migrate_permission_control(storage, config)?;

    Ok(())
}

fn migrate_permission_control(storage: &mut dyn Storage, config: Config) -> StdResult<()> {
    permission_control::set_governance(storage, &config.governance)
}

fn delete_config(storage: &mut dyn Storage) {
    CONFIG.remove(storage)
}

#[cw_serde]
#[deprecated(since = "0.4.1", note = "Only used during migrations")]
pub struct Config {
    pub governance: Addr,
}

#[deprecated(since = "0.4.1", note = "Only used during migrations")]
pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::permission_control;
    use axelar_wasm_std::permission_control::Permission;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};

    use crate::contract::migrations::v0_4_1;
    use crate::contract::CONTRACT_NAME;
    use crate::msg::InstantiateMsg;

    const GOVERNANCE: &str = "governance";

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v0_4_1::BASE_VERSION)
            .unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage).is_ok());
    }
    #[test]
    fn migrate_to_permission_control() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(v0_4_1::migrate(deps.as_mut().storage).is_ok());

        assert!(
            permission_control::sender_role(&deps.storage, &Addr::unchecked(GOVERNANCE))
                .unwrap()
                .contains(Permission::Governance)
        );
    }

    #[test]
    fn migrate_deletes_config() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        assert!(v0_4_1::migrate(deps.as_mut().storage).is_ok());

        assert!(v0_4_1::CONFIG.load(&deps.storage).is_err())
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_account: GOVERNANCE.to_string(),
            },
        )
        .unwrap();
    }
    #[deprecated(since = "0.4.1", note = "Only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v0_4_1::BASE_VERSION)?;

        v0_4_1::CONFIG.save(
            deps.storage,
            &v0_4_1::Config {
                governance: deps.api.addr_validate(&msg.governance_account)?,
            },
        )?;
        Ok(Response::default())
    }
}
