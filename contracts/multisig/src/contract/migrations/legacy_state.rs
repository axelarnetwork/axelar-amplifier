use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use router_api::ChainName;

#[cw_serde]
pub struct Config {
    pub rewards_contract: Addr,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a signing session expires
}

const CONFIG: Item<Config> = Item::new("config");

pub fn load_config(storage: &dyn Storage) -> Result<Config, cosmwasm_std::StdError> {
    CONFIG.load(storage)
}

pub const AUTHORIZED_CALLERS: Map<&Addr, ChainName> = Map::new("authorized_callers");

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub admin_address: String,
    pub rewards_address: String,
    pub block_expiry: nonempty::Uint64,
}

#[cfg(test)]
pub mod test {
    use axelar_wasm_std::error::ContractError;
    use axelar_wasm_std::{address, permission_control};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

    use super::{Config, InstantiateMsg, CONFIG};

    const CONTRACT_NAME: &str = "multisig";
    const CONTRACT_VERSION: &str = "2.1.0";

    pub fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
        let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

        permission_control::set_admin(deps.storage, &admin)?;
        permission_control::set_governance(deps.storage, &governance)?;

        let config = Config {
            rewards_contract: address::validate_cosmwasm_address(deps.api, &msg.rewards_address)?,
            block_expiry: msg.block_expiry,
        };
        CONFIG.save(deps.storage, &config)?;

        Ok(Response::default())
    }
}
