use std::fmt::Debug;

use axelar_wasm_std::{FnExt, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};
use router_api::{Address, ChainName};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::Config;
use crate::{state, TokenId};

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("contract config is missing")]
    ConfigMissing,
    #[error("invalid store access")]
    InvalidStoreAccess,
    #[error("invalid address")]
    InvalidAddress,
    #[error("untrusted source address {0}")]
    UntrustedAddress(Address),
    #[error("failed to execute ITS command")]
    Execute,
    #[error("unauthorized")]
    Unauthorized,
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("untrusted sender")]
    UntrustedSender,
    #[error("failed to update balance on chain {0} for token id {1}")]
    BalanceUpdateFailed(ChainName, TokenId),
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // Implement migration logic if needed
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _: Env,
    _: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let gateway = deps
        .api
        .addr_validate(&msg.gateway_address)
        .change_context(Error::InvalidAddress)
        .attach_printable(msg.gateway_address.clone())?;

    state::save_config(
        deps.storage,
        &Config {
            chain_name: msg.chain_name,
            gateway,
        },
    )?;

    if let Some(trusted_addresses) = msg.trusted_addresses {
        for (chain, address) in trusted_addresses {
            state::save_trusted_address(deps.storage, &chain, &address)?;
        }
    }

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let msg = msg.ensure_permissions(deps.storage, &info.sender, match_gateway)?;

    match msg {
        ExecuteMsg::Execute {
            cc_id,
            source_address,
            payload,
        } => execute::execute_message(deps, cc_id, source_address, payload),
        ExecuteMsg::UpdateTrustedAddress { chain, address } => {
            execute::update_trusted_address(deps, chain, address)
        }
    }?
    .then(Ok)
}

fn match_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage)
        .change_context(Error::ConfigMissing)?
        .gateway)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::TrustedAddress { chain } => query::trusted_address(deps, chain)?,
        QueryMsg::AllTrustedAddresses {} => query::all_trusted_addresses(deps)?,
        QueryMsg::TokenBalance { chain, token_id } => query::token_balance(deps, chain, token_id)?,
    }
    .then(Ok)
}
