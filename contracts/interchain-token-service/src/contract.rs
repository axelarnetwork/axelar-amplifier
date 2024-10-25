use std::fmt::Debug;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, killswitch, permission_control, FnExt, IntoContractError};
use axelarnet_gateway::AxelarExecutableMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};

use crate::events::Event;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

pub use execute::Error as ExecuteError;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to execute a cross-chain message")]
    Execute,
    #[error("failed to register an its edge contract")]
    RegisterItsContract,
    #[error("failed to deregsiter an its edge contract")]
    DeregisterItsContract,
    #[error("failed to query its address")]
    QueryItsContract,
    #[error("failed to query all its addresses")]
    QueryAllItsContracts,
    #[error("failed to disable execution")]
    DisableExecution,
    #[error("failed to enable execution")]
    EnableExecution,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    // Implement migration logic if needed

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _: Env,
    _: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let axelarnet_gateway =
        address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway_address)?;

    state::save_config(deps.storage, &Config { axelarnet_gateway })?;

    for (chain, address) in msg.its_contracts.iter() {
        state::save_its_contract(deps.storage, chain, address)?;
    }

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    Ok(Response::new().add_events(
        msg.its_contracts
            .into_iter()
            .map(|(chain, address)| Event::ItsContractRegistered { chain, address }.into()),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender, match_gateway)? {
        ExecuteMsg::Execute(AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }) => execute::execute_message(deps, cc_id, source_address, payload)
            .change_context(Error::Execute),
        ExecuteMsg::RegisterItsContract { chain, address } => {
            execute::register_its_contract(deps, chain, address)
                .change_context(Error::RegisterItsContract)
        }
        ExecuteMsg::DeregisterItsContract { chain } => {
            execute::deregister_its_contract(deps, chain)
                .change_context(Error::DeregisterItsContract)
        }
        ExecuteMsg::DisableExecution => {
            execute::disable_execution(deps).change_context(Error::DisableExecution)
        }
        ExecuteMsg::EnableExecution => {
            execute::enable_execution(deps).change_context(Error::EnableExecution)
        }
    }?
    .then(Ok)
}

fn match_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage).axelarnet_gateway)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ItsContract { chain } => {
            query::its_contracts(deps, chain).change_context(Error::QueryItsContract)
        }
        QueryMsg::AllItsContracts => {
            query::all_its_contracts(deps).change_context(Error::QueryAllItsContracts)
        }
    }?
    .then(Ok)
}
