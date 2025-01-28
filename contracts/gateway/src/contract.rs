use std::fmt::Debug;

use axelar_wasm_std::{address, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{ensure, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::VersionError;
use error_stack::{report, ResultExt};
use router_api::client::Router;
use semver::Version;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
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
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let old_version = Version::parse(&cw2::get_contract_version(deps.storage)?.version)?;
    ensure!(
        old_version.major == 1 && old_version.minor == 1,
        report!(VersionError::WrongVersion {
            expected: "1.1.x".into(),
            found: old_version.to_string()
        })
    );

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

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
    let verifier = client::ContractClient::new(deps.querier, &config.verifier).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::VerifyMessages(msgs) => {
            execute::verify_messages(&verifier, msgs).change_context(Error::VerifyMessages)
        }
        ExecuteMsg::RouteMessages(msgs) => {
            let router = Router::new(config.router);

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
mod test {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::Empty;

    use crate::contract::{instantiate, migrate, CONTRACT_NAME, CONTRACT_VERSION};
    use crate::msg::InstantiateMsg;

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make("sender"), &[]);
        let instantiate_msg = InstantiateMsg {
            verifier_address: api.addr_make("verifier").to_string(),
            router_address: api.addr_make("router").to_string(),
        };

        assert_ok!(instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            instantiate_msg
        ));

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
