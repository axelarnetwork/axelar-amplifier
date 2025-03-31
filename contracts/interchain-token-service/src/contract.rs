use std::fmt::Debug;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, killswitch, permission_control, FnExt, IntoContractError};
use axelarnet_gateway::AxelarExecutableMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};
use execute::{freeze_chain, unfreeze_chain};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod migrations;
mod query;

pub use execute::Error as ExecuteError;
pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to execute a cross-chain message")]
    Execute,
    #[error("failed to register chains")]
    RegisterChains,
    #[error("failed to register p2p token instance")]
    RegisterP2pTokenInstance,
    #[error("failed to update chain")]
    UpdateChain,
    #[error("failed to freeze chain")]
    FreezeChain,
    #[error("failed to unfreeze chain")]
    UnfreezeChain,
    #[error("failed to set chain config")]
    SetChainConfig,
    #[error("failed to disable execution")]
    DisableExecution,
    #[error("failed to enable execution")]
    EnableExecution,
    #[error("failed to query chain config")]
    QueryChainConfig,
    #[error("failed to query all its addresses")]
    QueryAllItsContracts,
    #[error("failed to query a specific token instance")]
    QueryTokenInstance,
    #[error("failed to query the token config")]
    QueryTokenConfig,
    #[error("failed to query the status of contract")]
    QueryContractStatus,
    #[error("failed to query chain configs")]
    QueryAllChainConfigs,
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

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    Ok(Response::new())
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
        ExecuteMsg::RegisterP2pTokenInstance {
            chain,
            token_id,
            origin_chain,
            decimals,
            supply,
        } => execute::register_p2p_token_instance(
            deps,
            token_id,
            chain,
            origin_chain,
            decimals,
            supply,
        )
        .change_context(Error::RegisterP2pTokenInstance),
        ExecuteMsg::RegisterChains { chains } => {
            execute::register_chains(deps, chains).change_context(Error::RegisterChains)
        }
        ExecuteMsg::UpdateChains { chains } => {
            execute::update_chains(deps, chains).change_context(Error::UpdateChain)
        }
        ExecuteMsg::FreezeChain { chain } => {
            freeze_chain(deps, chain).change_context(Error::FreezeChain)
        }
        ExecuteMsg::UnfreezeChain { chain } => {
            unfreeze_chain(deps, chain).change_context(Error::UnfreezeChain)
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
        QueryMsg::ItsChain { chain } => {
            query::its_chain(deps, chain).change_context(Error::QueryChainConfig)
        }
        QueryMsg::AllItsContracts => {
            query::all_its_contracts(deps).change_context(Error::QueryAllItsContracts)
        }
        QueryMsg::ItsChains {
            filter,
            start_after,
            limit,
        } => query::its_chains(deps, filter, start_after, limit)
            .change_context(Error::QueryAllChainConfigs),
        QueryMsg::TokenInstance { chain, token_id } => {
            query::token_instance(deps, chain, token_id).change_context(Error::QueryTokenInstance)
        }
        QueryMsg::TokenConfig { token_id } => {
            query::token_config(deps, token_id).change_context(Error::QueryTokenConfig)
        }
        QueryMsg::IsEnabled => {
            query::is_contract_enabled(deps).change_context(Error::QueryContractStatus)
        }
    }?
    .then(Ok)
}
