#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;
use router_api::error::Error;

use crate::contract::CONTRACT_NAME;
use crate::state;

const BASE_VERSION: &str = "0.4.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    set_generalized_permission_control(storage)?;
    Ok(())
}

fn set_generalized_permission_control(storage: &mut dyn Storage) -> Result<(), Error> {
    let old_config = CONFIG.load(storage)?;

    permission_control::set_governance(storage, &old_config.governance).map_err(Error::from)?;

    let new_config = &state::Config {
        rewards_denom: old_config.rewards_denom,
    };
    state::CONFIG.save(storage, new_config)?;
    Ok(())
}

#[cw_serde]
#[deprecated(since = "0.4.0", note = "only used during migration")]
pub struct Config {
    pub governance: Addr,
    pub rewards_denom: String,
}

#[deprecated(since = "0.4.0", note = "only used during migration")]
pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
pub mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

    use crate::contract::migrations::v0_4_0;
    use crate::contract::{execute, CONTRACT_NAME};
    use crate::msg::{ExecuteMsg, InstantiateMsg, Params};
    use crate::state;
    use crate::state::{Epoch, ParamsSnapshot, PARAMS};

    #[deprecated(since = "0.4.0", note = "only used during migration tests")]
    fn instantiate(
        deps: DepsMut,
        env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v0_4_0::BASE_VERSION)?;

        let governance = deps.api.addr_validate(&msg.governance_address)?;

        v0_4_0::CONFIG.save(
            deps.storage,
            &v0_4_0::Config {
                governance,
                rewards_denom: msg.rewards_denom,
            },
        )?;

        PARAMS.save(
            deps.storage,
            &ParamsSnapshot {
                params: msg.params,
                created_at: Epoch {
                    epoch_num: 0,
                    block_height_started: env.block.height,
                },
            },
        )?;

        Ok(Response::new())
    }

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut(), "denom");
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_4_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v0_4_0::BASE_VERSION)
            .unwrap();

        assert!(v0_4_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_config() {
        let mut deps = mock_dependencies();
        let denom = "denom".to_string();
        instantiate_contract(deps.as_mut(), &denom);

        v0_4_0::migrate(&mut deps.storage).unwrap();

        let new_config = state::CONFIG.load(&deps.storage).unwrap();
        assert_eq!(denom, new_config.rewards_denom);
    }

    #[test]
    fn migrate_governance_permission() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut(), "denom");

        v0_4_0::migrate(&mut deps.storage).unwrap();

        let msg = ExecuteMsg::UpdateParams {
            params: Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: 1000u128.try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
        };
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("anyone", &[]),
            msg.clone(),
        )
        .is_err());

        assert!(execute(deps.as_mut(), mock_env(), mock_info("governance", &[]), msg).is_ok());
    }

    #[deprecated(since = "0.4.0", note = "only used during migration tests")]
    pub fn instantiate_contract(deps: DepsMut, denom: impl Into<String>) {
        let msg = InstantiateMsg {
            governance_address: "governance".to_string(),
            rewards_denom: denom.into(),
            params: Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: 1000u128.try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
        };
        instantiate(deps, mock_env(), mock_info("anyone", &[]), msg).unwrap();
    }
}
