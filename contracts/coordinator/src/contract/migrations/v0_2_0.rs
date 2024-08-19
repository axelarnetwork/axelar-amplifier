use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use router_api::ChainName;

use crate::contract::CONTRACT_NAME;
use crate::error::ContractError;
use crate::state::save_prover_for_chain;

const BASE_VERSION: &str = "0.2.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    migrate_config_to_permission_control(storage)?;
    migrate_registered_provers(storage)?;
    Ok(())
}

fn migrate_config_to_permission_control(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let config = CONFIG.load(storage).map_err(ContractError::from)?;
    permission_control::set_governance(storage, &config.governance).map_err(ContractError::from)?;
    CONFIG.remove(storage);
    Ok(())
}

fn migrate_registered_provers(storage: &mut dyn Storage) -> Result<(), ContractError> {
    PROVER_PER_CHAIN
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .try_for_each(|(chain, prover)| save_prover_for_chain(storage, chain, prover))?;

    PROVER_PER_CHAIN.clear(storage);
    Ok(())
}

#[cw_serde]
#[deprecated(since = "0.2.0", note = "only used to test the migration")]
struct Config {
    pub governance: Addr,
}

#[deprecated(since = "0.2.0", note = "only used to test the migration")]
const CONFIG: Item<Config> = Item::new("config");

#[deprecated(since = "0.2.0", note = "only used to test the migration")]
const PROVER_PER_CHAIN: Map<ChainName, Addr> = Map::new("prover_per_chain");

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
    use router_api::ChainName;

    use super::PROVER_PER_CHAIN;
    use crate::contract::migrations::v0_2_0;
    use crate::contract::migrations::v0_2_0::BASE_VERSION;
    use crate::contract::{execute, CONTRACT_NAME};
    use crate::error::ContractError;
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::state::{is_prover_registered, load_prover_by_chain};

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

    #[test]
    fn ensure_registered_provers_are_migrated() {
        let mut deps = mock_dependencies();
        instantiate_0_2_0_contract(deps.as_mut()).unwrap();

        let provers: Vec<(ChainName, Addr)> = vec![
            ("chain1".parse().unwrap(), Addr::unchecked("addr1")),
            ("chain2".parse().unwrap(), Addr::unchecked("addr2")),
        ];

        for (chain, prover) in &provers {
            register_prover_0_2_0(deps.as_mut(), chain.clone(), prover.clone()).unwrap();
        }

        assert!(v0_2_0::migrate(deps.as_mut().storage).is_ok());

        for (chain, prover) in provers {
            assert_eq!(
                load_prover_by_chain(deps.as_ref().storage, chain).unwrap(),
                prover.clone()
            );

            // check index is working as well
            assert!(is_prover_registered(deps.as_ref().storage, prover).unwrap());
        }

        assert!(PROVER_PER_CHAIN.is_empty(deps.as_ref().storage));
    }

    fn instantiate_0_2_0_contract(
        deps: DepsMut,
    ) -> Result<InstantiateMsg, axelar_wasm_std::error::ContractError> {
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

    #[deprecated(since = "0.2.0", note = "only used to test the migration")]
    fn register_prover_0_2_0(
        deps: DepsMut,
        chain_name: ChainName,
        new_prover_addr: Addr,
    ) -> Result<Response, ContractError> {
        PROVER_PER_CHAIN.save(deps.storage, chain_name.clone(), &(new_prover_addr))?;
        Ok(Response::new())
    }
}
