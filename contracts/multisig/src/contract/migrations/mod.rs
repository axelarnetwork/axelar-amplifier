mod legacy_state;

use std::collections::{HashMap, HashSet};

use axelar_wasm_std::{address, migrate_from_version};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Order, Response};
use router_api::ChainName;

use crate::contract::migrations::legacy_state::AUTHORIZED_CALLERS;
use crate::state::{save_prover, Config, CONFIG};

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator: String,
    pub default_authorized_provers: HashMap<ChainName, Addr>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("2.1")]
pub fn migrate(
    mut deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = legacy_state::load_config(deps.storage)?;

    let coordinator = address::validate_cosmwasm_address(deps.api, msg.coordinator.as_str())?;

    CONFIG.save(
        deps.storage,
        &Config {
            rewards_contract: config.rewards_contract,
            block_expiry: config.block_expiry,
            coordinator,
        },
    )?;

    migrate_authorized_callers(&mut deps, msg.default_authorized_provers)?;

    Ok(Response::default())
}

fn migrate_authorized_callers(
    deps: &mut DepsMut,
    authorized_provers: HashMap<ChainName, Addr>,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    let mut seen = HashMap::<ChainName, Addr>::new();
    let mut duplicates = HashSet::<ChainName>::new();

    for result in AUTHORIZED_CALLERS
        .range(deps.storage, None, None, Order::Ascending)
        .filter_map(|result| result.ok())
    {
        let (prover_addr, chain_name) = result;

        if seen.contains_key(&chain_name) {
            duplicates.insert(chain_name.clone());
        }
        seen.insert(chain_name, prover_addr);
    }

    for (chain_name, prover_addr) in seen {
        let addr = if duplicates.contains(&chain_name) {
            authorized_provers
                .get(&chain_name)
                .cloned()
                .unwrap_or(prover_addr)
        } else {
            prover_addr
        };
        save_prover(deps.storage, addr, chain_name)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use axelar_wasm_std::address;
    use axelar_wasm_std::nonempty::Uint64;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use router_api::{chain_name, cosmos_addr, ChainName};

    use super::legacy_state;
    use crate::contract::migrations::legacy_state::AUTHORIZED_CALLERS;
    use crate::contract::{migrate, MigrateMsg};
    use crate::state::{prover_by_chain, CONFIG};

    const REWARDS: &str = "rewards";

    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";
    const COORDINATOR: &str = "coordinator";
    const SENDER: &str = "sender";
    const PROVER1: &str = "prover1";
    const PROVER2: &str = "prover2";

    #[test]
    fn migrate_properly_registers_coordinator() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(legacy_state::test::instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            legacy_state::InstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                admin_address: cosmos_addr!(ADMIN).to_string(),
                rewards_address: cosmos_addr!(REWARDS).to_string(),
                block_expiry: Uint64::try_from(100).unwrap(),
            },
        )
        .is_ok());

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                coordinator: cosmos_addr!(COORDINATOR).to_string(),
                default_authorized_provers: HashMap::new(),
            },
        )
        .is_ok());

        let res = CONFIG.load(&deps.storage);
        assert!(res.is_ok());
        let coord_addr =
            address::validate_cosmwasm_address(&deps.api, cosmos_addr!(COORDINATOR).as_ref());
        assert!(coord_addr.is_ok());
        assert_eq!(res.unwrap().coordinator, coord_addr.unwrap());
    }

    #[test]
    fn migrate_stores_authorized_callers_for_chains() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(GOVERNANCE), &[]);

        assert!(legacy_state::test::instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            legacy_state::InstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                admin_address: cosmos_addr!(ADMIN).to_string(),
                rewards_address: cosmos_addr!(REWARDS).to_string(),
                block_expiry: Uint64::try_from(100).unwrap(),
            },
        )
        .is_ok());

        assert!(AUTHORIZED_CALLERS
            .save(
                &mut deps.storage,
                &cosmos_addr!(PROVER2),
                &ChainName::from_str("chain1").unwrap()
            )
            .is_ok());

        assert!(AUTHORIZED_CALLERS
            .save(
                &mut deps.storage,
                &cosmos_addr!(PROVER1),
                &ChainName::from_str("chain1").unwrap()
            )
            .is_ok());

        let res = prover_by_chain(&deps.storage, chain_name!("chain1"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                coordinator: cosmos_addr!(COORDINATOR).to_string(),
                default_authorized_provers: HashMap::new(),
            },
        )
        .is_ok());

        let res = prover_by_chain(&deps.storage, chain_name!("chain1"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Some(cosmos_addr!(PROVER2)));
    }

    #[test]
    fn migrate_stores_authorized_callers_for_chains_using_default_provers() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(GOVERNANCE), &[]);

        assert!(legacy_state::test::instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            legacy_state::InstantiateMsg {
                governance_address: cosmos_addr!(GOVERNANCE).to_string(),
                admin_address: cosmos_addr!(ADMIN).to_string(),
                rewards_address: cosmos_addr!(REWARDS).to_string(),
                block_expiry: Uint64::try_from(100).unwrap(),
            },
        )
        .is_ok());

        assert!(AUTHORIZED_CALLERS
            .save(
                &mut deps.storage,
                &cosmos_addr!(PROVER2),
                &ChainName::from_str("chain1").unwrap()
            )
            .is_ok());

        assert!(AUTHORIZED_CALLERS
            .save(
                &mut deps.storage,
                &cosmos_addr!(PROVER1),
                &ChainName::from_str("chain1").unwrap()
            )
            .is_ok());

        let res = prover_by_chain(&deps.storage, chain_name!("chain1"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                coordinator: cosmos_addr!(COORDINATOR).to_string(),
                default_authorized_provers: HashMap::from([(
                    chain_name!("chain1"),
                    cosmos_addr!(PROVER1)
                )]),
            },
        )
        .is_ok());

        let res = prover_by_chain(&deps.storage, chain_name!("chain1"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Some(cosmos_addr!(PROVER1)));
    }
}
