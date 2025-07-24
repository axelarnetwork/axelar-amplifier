use axelar_wasm_std::{address, migrate_from_version, nonempty};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, Response};
use cw_storage_plus::Item;

use crate::state::{Config, CONFIG};

#[cw_serde]
pub struct OldConfig {
    pub rewards_contract: Addr,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a signing session expires
}

pub const OLD_CONFIG: Item<OldConfig> = Item::new("config");

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
    let old_config = OLD_CONFIG.load(deps.storage)?;

    let coordinator = address::validate_cosmwasm_address(deps.api, msg.coordinator.as_str())?;

    CONFIG.save(
        deps.storage,
        &Config {
            rewards_contract: old_config.rewards_contract,
            block_expiry: old_config.block_expiry,
            coordinator,
        },
    )?;

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::nonempty::{self, Uint64};
    use axelar_wasm_std::{address, permission_control};
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

    use crate::contract::migrations::{OldConfig, OLD_CONFIG};
    use crate::contract::{migrate, MigrateMsg};
    use crate::state::CONFIG;

    const OLD_CONTRACT_NAME: &str = "multisig";
    const OLD_CONTRACT_VERSION: &str = "2.1.0";

    const REWARDS: &str = "rewards";

    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";
    const COORDINATOR: &str = "coordinator";
    const SENDER: &str = "sender";

    #[cw_serde]
    pub struct OldInstantiateMsg {
        pub governance_address: String,
        pub admin_address: String,
        pub rewards_address: String,
        pub block_expiry: nonempty::Uint64,
    }
    fn old_instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: OldInstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, OLD_CONTRACT_NAME, OLD_CONTRACT_VERSION)?;

        let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
        let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

        permission_control::set_admin(deps.storage, &admin)?;
        permission_control::set_governance(deps.storage, &governance)?;

        let config = OldConfig {
            rewards_contract: address::validate_cosmwasm_address(deps.api, &msg.rewards_address)?,
            block_expiry: msg.block_expiry,
        };
        OLD_CONFIG.save(deps.storage, &config)?;

        Ok(Response::default())
    }

    #[test]
    fn migrate_properly_registers_coordinator() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make(SENDER), &[]);

        assert!(old_instantiate(
            deps.as_mut(),
            env.clone(),
            info,
            OldInstantiateMsg {
                governance_address: api.addr_make(GOVERNANCE).to_string(),
                admin_address: api.addr_make(ADMIN).to_string(),
                rewards_address: api.addr_make(REWARDS).to_string(),
                block_expiry: Uint64::try_from(100).unwrap(),
            },
        )
        .is_ok());

        assert!(migrate(
            deps.as_mut(),
            env,
            MigrateMsg {
                coordinator: api.addr_make(COORDINATOR).to_string(),
            },
        )
        .is_ok());

        let res = CONFIG.load(&deps.storage);
        assert!(res.is_ok());
        let coord_addr =
            address::validate_cosmwasm_address(&deps.api, api.addr_make(COORDINATOR).as_ref());
        assert!(coord_addr.is_ok());
        assert_eq!(res.unwrap().coordinator, coord_addr.unwrap());
    }
}
