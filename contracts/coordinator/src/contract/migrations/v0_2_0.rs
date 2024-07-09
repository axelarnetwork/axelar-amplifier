use crate::contract::CONTRACT_NAME;
use crate::error::ContractError;
use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;

const BASE_VERSION: &str = "0.2.0";

pub(crate) fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    migrate_config_to_permission_control(storage)?;
    Ok(())
}

fn migrate_config_to_permission_control(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let config = CONFIG.load(storage).map_err(ContractError::from)?;
    permission_control::set_governance(storage, &config.governance).map_err(ContractError::from)?;
    CONFIG.remove(storage);
    Ok(())
}

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::contract::migrations::v0_2_0;
    use crate::contract::migrations::v0_2_0::BASE_VERSION;
    use crate::contract::{execute, CONTRACT_NAME};
    use crate::error::ContractError;
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        let _ = instantiate_0_2_0_contract(deps.as_mut()).unwrap();
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_2_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(v0_2_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn ensure_governance_is_migrated_to_permission_control() {
        let mut deps = mock_dependencies();

        let msg = instantiate_0_2_0_contract(deps.as_mut()).unwrap();

        assert!(v0_2_0::CONFIG.may_load(&deps.storage).unwrap().is_some());

        assert!(v0_2_0::migrate(deps.as_mut().storage).is_ok());

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
            mock_info(&msg.governance_address, &[]),
            ExecuteMsg::RegisterProverContract {
                chain_name: "chain".parse().unwrap(),
                new_prover_addr: Addr::unchecked("any_addr"),
            },
        )
        .is_ok());

        assert!(v0_2_0::CONFIG.may_load(&deps.storage).unwrap().is_none())
    }

    fn instantiate_0_2_0_contract(
        deps: DepsMut,
    ) -> Result<InstantiateMsg, axelar_wasm_std::ContractError> {
        let governance = "governance";

        let msg = InstantiateMsg {
            governance_address: governance.to_string(),
        };
        instantiate_0_2_0(deps, mock_env(), mock_info("sender", &[]), msg.clone())?;
        Ok(msg)
    }

    #[deprecated(since = "0.2.0", note = "only used to test the migration")]
    fn instantiate_0_2_0(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

        v0_2_0::CONFIG.save(
            deps.storage,
            &v0_2_0::Config {
                governance: deps.api.addr_validate(&msg.governance_address)?,
            },
        )?;
        Ok(Response::default())
    }
}
