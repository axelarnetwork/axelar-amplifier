use std::fmt::Debug;

use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use error_stack::ResultExt;
use router_api::CrossChainId;
use router_api::client::Router;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,
    #[error("failed to execute gateway command")]
    Execute,
    #[error("unable to generate event index")]
    EventIndex,
    #[error("invalid cross-chain id")]
    InvalidCrossChainId,
    #[error("failed to query message status")]
    MessageStatus,
    #[error("message with ID {0} was not sent from Axelar")]
    OnlyAxelar(CrossChainId),
    #[error("message with ID {0} was not sent from the ITS hub")]
    OnlyItsHub(CrossChainId),
    #[error("failed to query outgoing messages")]
    OutgoingMessages,
    #[error("payload hash mismatch")]
    PayloadHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("router only")]
    RouterOnly,
    #[error("failed to save outgoing message")]
    SaveOutgoingMessage,
    #[error("failed to query token info")]
    TokenInfo,
    #[error("invalid token")]
    InvalidToken,
    #[error("invalid address")]
    InvalidAddress
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
    _env: Env,
    _msg: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let router = address::validate_cosmwasm_address(deps.api, &msg.router_address)?;
    let verifier = address::validate_cosmwasm_address(deps.api, &msg.verifier_address)?;
    let its_hub = address::validate_cosmwasm_address(deps.api, &msg.its_hub_address)?;

    state::save_config(deps.storage, &Config {
        verifier,
        router,
        its_hub,
        axelar_chain_name: msg.axelar_chain_name,
        xrpl_chain_name: msg.xrpl_chain_name,
        xrpl_multisig: msg.xrpl_multisig_address,
    })?;

    permission_control::set_admin(deps.storage, &deps.api.addr_validate(&msg.admin_address)?)?;
    permission_control::set_governance(
        deps.storage,
        &deps.api.addr_validate(&msg.governance_address)?,
    )?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = state::load_config(deps.storage).change_context(Error::Execute)?;
    let verifier = client::ContractClient::new(deps.querier, &config.verifier).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::RegisterLocalInterchainToken { xrpl_token } => {
            execute::register_local_interchain_token(
                deps.storage,
                xrpl_token,
            )
        }
        ExecuteMsg::RegisterRemoteInterchainToken {
            token_id,
            xrpl_currency,
            canonical_decimals,
        } => {
            execute::register_remote_interchain_token(
                deps.storage,
                config.xrpl_multisig,
                token_id,
                xrpl_currency,
                canonical_decimals,
            )
        }
        ExecuteMsg::DeployXrpToSidechain {
            sidechain_name,
            deployment_params,
        } => {
            let router = Router::new(config.router);
            execute::deploy_xrp_to_sidechain(
                env.block.height,
                &router,
                &config.its_hub,
                &config.axelar_chain_name,
                &config.xrpl_chain_name,
                &sidechain_name,
                config.xrpl_multisig,
                deployment_params,
            )
        }
        ExecuteMsg::DeployInterchainToken {
            xrpl_token,
            destination_chain,
            token_params,
        } => {
            let router = Router::new(config.router);
            execute::deploy_interchain_token(
                env.block.height,
                &router,
                &config.its_hub,
                &config.axelar_chain_name,
                config.xrpl_multisig,
                &config.xrpl_chain_name,
                xrpl_token,
                destination_chain,
                token_params,
            )
        }
        ExecuteMsg::VerifyMessages(msgs) => {
            execute::verify_messages(&verifier, msgs, &config.xrpl_chain_name)
        }
        // Should be called RouteOutgoingMessage.
        // Called RouteMessages for compatibility with the router.
        ExecuteMsg::RouteMessages(msgs) => {
            let router = Router::<Empty>::new(config.router);
            if info.sender != router.address {
                return Err(Error::RouterOnly).map_err(axelar_wasm_std::error::ContractError::from)
            }

            execute::route_outgoing_messages(
                deps.storage,
                msgs,
                config.its_hub,
                &config.axelar_chain_name,
            )
        }
        ExecuteMsg::RouteIncomingMessages(msgs) => {
            let router = Router::new(config.router);
            execute::route_incoming_messages(
                deps.storage,
                &verifier,
                &router,
                msgs,
                &config.its_hub,
                &config.axelar_chain_name,
                &config.xrpl_multisig,
                &config.xrpl_chain_name,
            )
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
        QueryMsg::OutgoingMessages(message_ids) => {
            query::outgoing_messages(deps.storage, message_ids.iter())
                .change_context(Error::OutgoingMessages)
        }
        QueryMsg::TokenInfo(token_id) => {
            query::token_info(deps.storage, token_id)
                .change_context(Error::TokenInfo)
        }
    }?
    .then(Ok)
}
