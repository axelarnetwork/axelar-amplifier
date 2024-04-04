use connection_router_api::CrossChainId;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response};
use gateway_api::msg::{ExecuteMsg, QueryMsg};
use std::fmt::Debug;

use crate::msg::InstantiateMsg;

mod execute;
mod query;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    Ok(internal::instantiate(deps, env, info, msg)?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    Ok(internal::execute(deps, env, info, msg)?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::ContractError> {
    Ok(internal::query(deps, env, msg)?)
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gateway contract config is missing")]
    ConfigMissing,
    #[error("invalid store access")]
    InvalidStoreAccess,
    #[error("failed to serialize the response")]
    SerializeResponse,
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,
    #[error("invalid address")]
    InvalidAddress,
    #[error("failed to query message status")]
    MessageStatus,
    #[error("message with ID {0} not found")]
    MessageNotFound(CrossChainId),
}

mod internal {
    use aggregate_verifier::client::Verifier;
    use connection_router_api::client::Router;
    use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};
    use error_stack::{Result, ResultExt};
    use gateway_api::msg::{ExecuteMsg, QueryMsg};

    use crate::contract::Error;
    use crate::msg::InstantiateMsg;
    use crate::state::Config;
    use crate::{contract, state};

    pub(crate) fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, Error> {
        let router = deps
            .api
            .addr_validate(&msg.router_address)
            .change_context(Error::InvalidAddress)
            .attach_printable(msg.router_address)?;

        let verifier = deps
            .api
            .addr_validate(&msg.verifier_address)
            .change_context(Error::InvalidAddress)
            .attach_printable(msg.verifier_address)?;

        state::save_config(deps.storage, &Config { verifier, router })
            .change_context(Error::InvalidStoreAccess)?;

        Ok(Response::new())
    }

    pub(crate) fn execute(
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        msg: ExecuteMsg,
    ) -> Result<Response, Error> {
        let config = state::load_config(deps.storage).change_context(Error::ConfigMissing)?;
        let verifier = Verifier {
            address: config.verifier,
            querier: deps.querier,
        };

        let router = Router {
            address: config.router,
        };

        match msg {
            ExecuteMsg::VerifyMessages(msgs) => contract::execute::verify_messages(&verifier, msgs),
            ExecuteMsg::RouteMessages(msgs) => {
                if info.sender == router.address {
                    contract::execute::route_outgoing_messages(deps.storage, msgs)
                } else {
                    contract::execute::route_incoming_messages(&verifier, &router, msgs)
                }
            }
        }
    }

    pub(crate) fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, Error> {
        match msg {
            QueryMsg::GetOutgoingMessages { message_ids } => {
                let msgs = contract::query::get_outgoing_messages(deps.storage, message_ids)?;
                to_json_binary(&msgs).change_context(Error::SerializeResponse)
            }
        }
    }
}
