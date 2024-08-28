use axelar_wasm_std::{address, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use error_stack::ResultExt;
use router_api::client::Router;
use router_api::CrossChainId;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{self, Config};

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("contract config is missing")]
    ConfigMissing,
    #[error("invalid store access")]
    InvalidStoreAccess,
    #[error("failed to serialize the response")]
    SerializeResponse,
    #[error("failed to serialize wasm message")]
    SerializeWasmMsg,
    #[error("invalid address {0}")]
    InvalidAddress(String),
    #[error("invalid message id")]
    InvalidMessageId,
    #[error("failed to save outgoing message")]
    SaveOutgoingMessage,
    #[error("message with ID {0} not found")]
    MessageNotFound(CrossChainId),
    #[error("message with ID {0} is different")]
    MessageMismatch(CrossChainId),
    #[error("message with ID {0} not in approved status")]
    MessageNotApproved(CrossChainId),
    #[error("failed to set message with ID {0} as executed")]
    SetMessageStatusExecutedFailed(CrossChainId),
    #[error("payload hash doesn't match message")]
    PayloadHashMismatch,
    #[error("failed to route messages")]
    RoutingFailed,
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
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let router = address::validate_cosmwasm_address(deps.api, &msg.router_address)?;

    let config = Config {
        chain_name: msg.chain_name,
        router,
    };

    state::save_config(deps.storage, &config).change_context(Error::InvalidStoreAccess)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let msg = msg.ensure_permissions(deps.storage, &info.sender)?;

    let config = state::load_config(deps.storage).change_context(Error::ConfigMissing)?;

    let router = Router {
        address: config.router,
    };
    let chain_name = config.chain_name;

    match msg {
        ExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        } => execute::call_contract(
            deps.storage,
            env.block.height,
            &router,
            chain_name,
            info.sender,
            destination_chain,
            destination_address,
            payload,
        ),
        ExecuteMsg::RouteMessages(msgs) => {
            if info.sender == router.address {
                execute::receive_messages(deps.storage, chain_name, msgs)
            } else {
                // Messages initiated via call contract can be routed again
                execute::send_messages(deps.storage, &router, msgs)
            }
        }
        ExecuteMsg::Execute { cc_id, payload } => {
            execute::execute(deps.storage, deps.api, deps.querier, cc_id, payload)
        }
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::SentMessages { cc_ids } => to_json_binary(&query::sent_messages(deps, cc_ids)?),
        QueryMsg::ReceivedMessages { cc_ids } => {
            to_json_binary(&query::received_messages(deps, cc_ids)?)
        }
        QueryMsg::ChainName => to_json_binary(&state::load_config(deps.storage)?.chain_name),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
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
