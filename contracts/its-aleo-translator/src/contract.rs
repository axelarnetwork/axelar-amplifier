use aleo_gateway::network::NetworkConfig;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response};
use its_msg_translator_api::QueryMsg;
use snarkvm_cosmwasm::prelude::{CanaryV0, MainnetV0, Network, TestnetV0};

use crate::error::ContractError;
use crate::msg::{InstantiateMsg, MigrateMsg};
use crate::state::{Config, CONFIG};

mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(
        deps.storage,
        &Config {
            network: msg.network,
        },
    )?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    match config.network {
        NetworkConfig::TestnetV0 => query_impl::<TestnetV0>(msg),
        NetworkConfig::MainnetV0 => query_impl::<MainnetV0>(msg),
        NetworkConfig::CanaryV0 => query_impl::<CanaryV0>(msg),
    }
}

fn query_impl<N: Network>(msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::FromBytes { payload } => query::from_bytes::<N>(payload),
        QueryMsg::ToBytes { message } => query::to_bytes::<N>(message),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(
        deps.storage,
        &Config {
            network: msg.network,
        },
    )?;

    Ok(Response::new())
}
