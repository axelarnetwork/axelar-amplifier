mod legacy_state;

use axelar_wasm_std::{address, migrate_from_version};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("2.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // Invokes minor version update
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

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::address;
    use axelar_wasm_std::nonempty::Uint64;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use router_api::cosmos_addr;

    use super::legacy_state;
    use crate::contract::{migrate, MigrateMsg};
    use crate::state::CONFIG;

    const REWARDS: &str = "rewards";

    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";
    const COORDINATOR: &str = "coordinator";
    const SENDER: &str = "sender";

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
}
