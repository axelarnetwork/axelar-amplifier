use std::fmt::Debug;

use axelar_wasm_std::{address, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use error_stack::ResultExt;
use gateway_api::msg::{ExecuteMsg, QueryMsg};
use router_api::client::Router;

use crate::msg::InstantiateMsg;
use crate::state;
use crate::state::Config;

mod execute;
mod migrations;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,
    #[error("failed to query message status")]
    MessageStatus,
    #[error("failed to verify messages")]
    VerifyMessages,
    #[error("failed to route outgoing messages to gateway")]
    RouteOutgoingMessages,
    #[error("failed to route messages from gateway to router")]
    RouteIncomingMessages,
    #[error("failed to query outgoing messages")]
    OutgoingMessages,
    #[error("failed to save outgoing message")]
    SaveOutgoingMessage,
    #[error("failed to execute gateway command")]
    Execute,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
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

    let router = address::validate_cosmwasm_address(deps.api, &msg.router_address)?;
    let verifier = address::validate_cosmwasm_address(deps.api, &msg.verifier_address)?;

    state::save_config(deps.storage, &Config { verifier, router })?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = state::load_config(deps.storage).change_context(Error::Execute)?;
    let verifier = client::Client::new(deps.querier, config.verifier).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::VerifyMessages(msgs) => {
            execute::verify_messages(&verifier, msgs).change_context(Error::VerifyMessages)
        }
        ExecuteMsg::RouteMessages(msgs) => {
            let router = Router {
                address: config.router,
            };

            if info.sender == router.address {
                execute::route_outgoing_messages(deps.storage, msgs)
                    .change_context(Error::RouteOutgoingMessages)
            } else {
                execute::route_incoming_messages(&verifier, &router, msgs)
                    .change_context(Error::RouteIncomingMessages)
            }
        }
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::OutgoingMessages(message_ids) => {
            query::outgoing_messages(deps.storage, message_ids.iter())
                .change_context(Error::OutgoingMessages)
        }
    }?
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, Addr, QuerierWrapper, WasmQuery};
    use gateway_api::client::Client;
    use gateway_api::msg::QueryMsg;
    use router_api::CrossChainId;

    use super::{instantiate, query};
    use crate::msg::InstantiateMsg;

    const ROUTER: &str = "router";
    const VERIFIER: &str = "verifier";
    const GATEWAY: &str = "gateway";

    fn setup() -> MockQuerier {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                router_address: Addr::unchecked(ROUTER).to_string(),
                verifier_address: Addr::unchecked(VERIFIER).to_string(),
            },
        )
        .unwrap();
        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == GATEWAY => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        querier
    }

    #[test]
    fn query_outgoing_messages_should_return_error_when_messages_are_not_found() {
        let querier = setup();

        let addr = Addr::unchecked(GATEWAY);
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let cc_id = CrossChainId {
            source_chain: "ethereum".parse().unwrap(),
            message_id: "0x13548ac28fe95805ad2b8b824472d08e3b45cbc023a5a45a912f11ea98f81e97-0"
                .parse()
                .unwrap(),
        };
        let res = client.outgoing_messages(vec![cc_id.clone()]);
        assert_eq!(
            res.unwrap_err().to_string(),
            gateway_api::client::Error::QueryOutgoingMessages(vec![cc_id]).to_string()
        );
    }
}
