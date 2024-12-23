use std::fmt::Debug;

use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, HexBinary, MessageInfo, Response, StdError};
use error_stack::ResultExt;
use interchain_token_service::TokenId;
use router_api::{ChainNameRaw, CrossChainId};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenOrXrp};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("chain {0} already registered")]
    ChainAlreadyRegistered(ChainNameRaw),
    #[error("chain {0} not registered")]
    ChainNotRegistered(ChainNameRaw),
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,
    #[error("failed to execute gateway command")]
    Execute,
    #[error("unable to generate event index")]
    EventIndex,
    #[error("failed to offload dust")]
    FailedToOffloadDust,
    #[error("forbidden chain {0}")]
    ForbiddenChain(ChainNameRaw),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("invalid cross-chain id")]
    InvalidCrossChainId,
    #[error("invalid decimals {0}")]
    InvalidDecimals(u8),
    #[error("invalid destination address")]
    InvalidDestinationAddress,
    #[error("invalid drops {0}")]
    InvalidDrops(u64),
    #[error("invalid source address")]
    InvalidSourceAddress,
    #[error("invalid token")]
    InvalidToken,
    #[error(
        "invalid transfer amount {amount} to chain {destination_chain}"
    )]
    InvalidTransferAmount {
        destination_chain: ChainNameRaw,
        amount: XRPLPaymentAmount,
    },
    #[error("token {token_id} deployed mismatch: expected {expected}, actual {actual}")]
    LocalTokenDeployedMismatch {
        token_id: TokenId,
        expected: XRPLToken,
        actual: XRPLToken,
    },
    #[error("failed to query message status")]
    MessageStatus,
    #[error("no dust to offload for token {0}")]
    NoDustToOffload(TokenId),
    #[error("message with ID {0} was not sent from Axelar")]
    OnlyFromAxelar(CrossChainId),
    #[error("message with ID {0} was not sent from the ITS hub")]
    OnlyFromItsHub(CrossChainId),
    #[error("failed to query outgoing messages")]
    OutgoingMessages,
    #[error("payload given but payload hash is empty")]
    PayloadHashEmpty,
    #[error("payload hash {0} given without full payload")]
    PayloadHashGivenWithoutPayload(HexBinary),
    #[error("payload hash mismatch: expected {expected}, actual {actual}")]
    PayloadHashMismatch {
        expected: HexBinary,
        actual: HexBinary,
    },
    #[error("remote token {token_id} deployed XRPL currency mismatch: expected {expected}, actual {actual}")]
    RemoteTokenDeployedCurrencyMismatch {
        token_id: TokenId,
        expected: XRPLCurrency,
        actual: XRPLCurrency,
    },
    #[error("remote token with XRPL currency {xrpl_currency} deployed token ID mismatch: expected {expected}, actual {actual}")]
    RemoteTokenDeployedIdMismatch {
        xrpl_currency: XRPLCurrency,
        expected: TokenId,
        actual: TokenId,
    },
    #[error("remote token {token_id} deployed XRPL issuer mismatch: expected {expected}, actual {actual}")]
    RemoteTokenDeployedIssuerMismatch {
        token_id: TokenId,
        expected: XRPLAccountId,
        actual: XRPLAccountId,
    },
    #[error("failed to save outgoing message")]
    SaveOutgoingMessage,
    #[error("state error")]
    State,
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("token {token_id} deployed decimals mismatch: expected {expected}, actual {actual}")]
    TokenDeployedDecimalsMismatch {
        token_id: TokenId,
        expected: u8,
        actual: u8,
    },
    #[error("failed to query token instance decimals for token {token_id} on chain {chain_name}")]
    TokenInstanceDecimals {
        chain_name: ChainNameRaw,
        token_id: TokenId,
    },
    #[error("token {0} not local")]
    TokenNotLocal(XRPLTokenOrXrp),
    #[error("token {token_id} not registered for chain {chain_name}")]
    TokenNotRegisteredForChain {
        token_id: TokenId,
        chain_name: ChainNameRaw,
    },
    #[error("failed to query xrpl token {0}")]
    XrplToken(TokenId),
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
        axelar_chain: msg.axelar_chain_name,
        xrpl_chain: msg.xrpl_chain_name,
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
    let config = state::load_config(deps.storage);

    match msg.ensure_permissions(
        deps.storage,
        &info.sender,
        |_, _| Ok::<_, error_stack::Report<Error>>(config.router.clone()),
    )? {
        ExecuteMsg::RegisterLocalToken { xrpl_token } => {
            execute::register_local_token(
                deps.storage,
                xrpl_token,
            )
        }
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency,
        } => {
            execute::register_remote_token(
                deps.storage,
                config.xrpl_multisig,
                token_id,
                xrpl_currency,
            )
        }
        ExecuteMsg::RegisterTokenInstance {
            token_id,
            chain,
            decimals,
        } => {
            execute::register_token_instance(
                deps.storage,
                &config,
                token_id,
                chain,
                decimals,
            )
        }
        ExecuteMsg::DeployTokenManager {
            xrpl_token,
            destination_chain,
            deploy_token_manager,
        } => {
            execute::deploy_token_manager(
                deps.storage,
                &config,
                env.block.height,
                xrpl_token,
                destination_chain,
                deploy_token_manager,
            )
        }
        ExecuteMsg::DeployInterchainToken {
            xrpl_token,
            destination_chain,
            deploy_token,
        } => {
            execute::deploy_interchain_token(
                deps.storage,
                &config,
                env.block.height,
                xrpl_token,
                destination_chain,
                deploy_token,
            )
        }
        ExecuteMsg::VerifyMessages(msgs) => {
            let verifier = client::ContractClient::new(deps.querier, &config.verifier).into();
            execute::verify_messages(&verifier, msgs, &config.xrpl_chain)
        }
        // Should be called RouteOutgoingMessage.
        // Called RouteMessages for compatibility with the router.
        ExecuteMsg::RouteMessages(msgs) => {
            execute::route_outgoing_messages(
                deps.storage,
                msgs,
                config.its_hub,
                &config.axelar_chain,
            )
        }
        ExecuteMsg::RouteIncomingMessages(msgs) => {
            let verifier = client::ContractClient::new(deps.querier, &config.verifier).into();
            execute::route_incoming_messages(
                deps.storage,
                &config,
                &verifier,
                msgs,
            )
        }
        ExecuteMsg::OffloadDust { multisig_prover, token_id } => {
            execute::offload_dust(
                deps.storage,
                multisig_prover,
                token_id,
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
        QueryMsg::XrplToken(token_id) => {
            query::xrpl_token(deps.storage, token_id.clone())
                .change_context(Error::XrplToken(token_id))
        }
        QueryMsg::TokenInstanceDecimals { chain_name, token_id } => {
            query::token_instance_decimals(deps.storage, chain_name.clone(), token_id.clone())
                .change_context(Error::TokenInstanceDecimals {
                    chain_name,
                    token_id,
                })
        }
        QueryMsg::InterchainTransfer { message_with_payload } => {
            let config = state::load_config(deps.storage);
            query::translate_to_interchain_transfer(deps.storage, &config, &message_with_payload)
        }
    }?
    .then(Ok)
}
