use aleo_network_config::network::NetworkConfig;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use execute::verify_signature;
use signature_verifier_api::msg::{ExecuteMsg, QueryMsg};
use snarkvm_cosmwasm::prelude::{CanaryV0, MainnetV0, TestnetV0};

use crate::msg::{InstantiateMsg, Msg};
use crate::state::{Config, CONFIG};

pub mod execute;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
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
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let res = match config.network {
        NetworkConfig::TestnetV0 => verify::<TestnetV0>(msg.into()),
        NetworkConfig::MainnetV0 => verify::<MainnetV0>(msg.into()),
        NetworkConfig::CanaryV0 => verify::<CanaryV0>(msg.into()),
    };

    Ok(Response::new()
        .set_data(to_json_binary(&res?).map_err(axelar_wasm_std::error::ContractError::from)?))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let res = match config.network {
        NetworkConfig::TestnetV0 => verify::<TestnetV0>(msg.into()),
        NetworkConfig::MainnetV0 => verify::<MainnetV0>(msg.into()),
        NetworkConfig::CanaryV0 => verify::<CanaryV0>(msg.into()),
    };

    to_json_binary(&res?).map_err(axelar_wasm_std::error::ContractError::from)
}

fn verify<N: snarkvm_cosmwasm::prelude::Network>(
    msg: Msg,
) -> Result<bool, axelar_wasm_std::error::ContractError> {
    Ok(verify_signature::<N>(
        msg.signature,
        msg.message,
        msg.public_key,
    )?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(
        deps.storage,
        &Config {
            network: NetworkConfig::TestnetV0, // Default value for migration
        },
    )?;

    Ok(Response::new())
}
