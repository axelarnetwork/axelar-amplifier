use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract};
use crate::{Message, TokenId};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainNameRaw),
    #[error("unknown its address {0}")]
    UnknownItsContract(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("failed to register its contract for chain {0}")]
    FailedItsContractRegistration(ChainNameRaw),
    #[error("failed to deregister its contract for chain {0}")]
    FailedItsContractDeregistration(ChainNameRaw),
    #[error("chain config for {0} already set")]
    ChainConfigAlreadySet(ChainNameRaw),
    #[error("invalid chain max uint")]
    LoadChainConfig(ChainNameRaw),
    #[error("failed to save chain config for chain {0}")]
    SaveChainConfig(ChainNameRaw),
    #[error("failed to apply invariants for token {0}")]
    InvariantViolated(TokenId),
}

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message, applies balance tracking,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    ensure_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match HubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let destination_address = load_its_contract(deps.storage, &destination_chain)
                .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

            apply_invariants(
                deps.storage,
                cc_id.source_chain.clone(),
                destination_chain.clone(),
                &message,
            )?;

            let destination_payload = HubMessage::ReceiveFromHub {
                source_chain: cc_id.source_chain.clone(),
                message: message.clone(),
            }
            .abi_encode();

            Ok(send_to_destination(
                deps.storage,
                deps.querier,
                destination_chain.clone(),
                destination_address,
                destination_payload,
            )?
            .add_event(
                Event::MessageReceived {
                    cc_id,
                    destination_chain,
                    message,
                }
                .into(),
            ))
        }
        _ => bail!(Error::InvalidMessageType),
    }
}

fn normalize(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

/// Ensures that the source address of the cross-chain message is the registered ITS contract for the source chain.
fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_its_contract = load_its_contract(storage, source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(normalize(&destination_chain), destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_contract(
    deps: DepsMut,
    chain: ChainNameRaw,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_contract(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::FailedItsContractRegistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractRegistered { chain, address }.into()))
}

pub fn deregister_its_contract(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::remove_its_contract(deps.storage, &chain)
        .change_context_lazy(|| Error::FailedItsContractDeregistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractDeregistered { chain }.into()))
}

pub fn set_chain_config(
    deps: DepsMut,
    chain: ChainNameRaw,
    max_uint: nonempty::Uint256,
    max_target_decimals: u8,
) -> Result<Response, Error> {
    match state::may_load_chain_config(deps.storage, &chain)
        .change_context_lazy(|| Error::LoadChainConfig(chain.clone()))?
    {
        Some(_) => bail!(Error::ChainConfigAlreadySet(chain)),
        None => state::save_chain_config(deps.storage, &chain, max_uint, max_target_decimals)
            .change_context_lazy(|| Error::SaveChainConfig(chain))?
            .then(|_| Ok(Response::new())),
    }
}

/// Applies invariants on the ITS message.
///
/// Invariants:
/// - Token must be deployed on the source/destination chains before any transfers can be routed.
/// - Token must not be already deployed during deployment.
/// - If the token is deployed without a custom minter, then the token is considered to be owned by ITS, and total token balance moved to the chain is tracked.
/// - If the total token amount moved to a chain so far is `x`, then any transfer moving the token back from the chain and exceeding `x` will fail.
///
/// Invariants are updated depending on the ITS message type
///
/// 1. InterchainTransfer:
///    - Decreases the token balance on the source chain, unless it's the origin chain in which case it's increased.
///    - Increases the token balance on the destination chain, unless it's the origin chain in which case it's decreased.
///    - If the balance underflows for either case, an error is returned.
///
/// 2. DeployInterchainToken:
///    - If a custom minter is not set, then the token balance is tracked for the source/destination chain.
///    - If the custom minter is set, then the balance is not tracked, but the deployment is recorded.
///
/// 3. DeployTokenManager:
///    - Same as the custom minter being set case.
fn apply_invariants(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
    message: &Message,
) -> Result<(), Error> {
    match message {
        Message::InterchainTransfer {
            token_id, amount, ..
        } => {
            // Update the balance on the source chain
            state::update_token_balance(
                storage,
                source_chain.clone(),
                token_id.clone(),
                *amount,
                false,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;

            // Update the balance on the destination chain
            state::update_token_balance(
                storage,
                destination_chain.clone(),
                token_id.clone(),
                *amount,
                true,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?
        }
        // Start balance tracking for the token on the destination chain when a token deployment is seen
        // No invariants can be assumed on the source since the token might pre-exist on the source chain
        Message::DeployInterchainToken {
            token_id,
            minter: None,
            ..
        } => {
            state::start_token_balance(storage, source_chain.clone(), token_id.clone(), true, true)
                .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;

            state::start_token_balance(
                storage,
                destination_chain.clone(),
                token_id.clone(),
                false,
                true,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?
        }
        Message::DeployInterchainToken {
            token_id,
            minter: Some(_),
            ..
        }
        | Message::DeployTokenManager { token_id, .. } => {
            state::start_token_balance(
                storage,
                source_chain.clone(),
                token_id.clone(),
                true,
                false,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;

            state::start_token_balance(
                storage,
                destination_chain.clone(),
                token_id.clone(),
                false,
                false,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?
        }
    };

    Ok(())
}
