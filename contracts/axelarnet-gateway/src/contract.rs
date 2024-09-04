use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{address, FnExt, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use error_stack::ResultExt;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{self, Config};

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to make a cross-chain contract call")]
    CallContract,
    #[error("failed to route messages on the gateway")]
    RouteMessages,
    #[error("failed to execute a cross-chain execution payload")]
    Execute,
    #[error("failed to query routable messages")]
    QueryRoutableMessage,
    #[error("failed to query executable messages")]
    QueryExecutableMessages,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        chain_name: msg.chain_name,
        router: address::validate_cosmwasm_address(deps.api, &msg.router_address)?,
    };

    state::save_config(deps.storage, &config)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        } => execute::call_contract(
            deps.storage,
            env.block.height,
            info.sender,
            execute::CallContractData {
                destination_chain,
                destination_address,
                payload,
            },
        )
        .change_context(Error::CallContract),
        ExecuteMsg::RouteMessages(msgs) => execute::route_messages(deps.storage, info.sender, msgs)
            .change_context(Error::RouteMessages),
        ExecuteMsg::Execute { cc_id, payload } => {
            execute::execute(deps, cc_id, payload).change_context(Error::Execute)
        }
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::RoutableMessages { cc_ids } => to_json_binary(
            &query::routable_messages(deps.storage, cc_ids)
                .change_context(Error::QueryRoutableMessage)?,
        ),
        QueryMsg::ExecutableMessages { cc_ids } => to_json_binary(
            &query::executable_messages(deps.storage, cc_ids)
                .change_context(Error::QueryExecutableMessages)?,
        ),
        QueryMsg::ChainName => to_json_binary(&query::chain_name(deps.storage)),
    }?
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    use super::*;

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, "axelarnet-gateway");
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
