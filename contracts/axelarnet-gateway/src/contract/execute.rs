use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Api, Event, HexBinary, QuerierWrapper, Response, Storage, WasmMsg};
use error_stack::{report, Result, ResultExt};
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::contract::Error;
use crate::events::AxelarnetGatewayEvent;
use crate::executable::AxelarExecutableClient;
use crate::state::{self};

// TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it. Use a placeholder in the meantime.
const PLACEHOLDER_TX_HASH: [u8; 32] = [0u8; 32];

pub(crate) fn call_contract(
    store: &mut dyn Storage,
    router: &Router,
    chain_name: ChainName,
    sender: Addr,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let counter = state::increment_msg_counter(store).change_context(Error::InvalidStoreAccess)?;

    let message_id = HexTxHashAndEventIndex {
        tx_hash: PLACEHOLDER_TX_HASH,
        event_index: counter,
    }
    .to_string();

    let cc_id = CrossChainId {
        source_chain: chain_name.into(),
        message_id: nonempty::String::try_from(message_id)
            .change_context(Error::InvalidMessageId)?,
    };

    let payload_hash = Keccak256::digest(payload.as_slice()).into();

    let msg = Message {
        cc_id: cc_id.clone(),
        source_address: Address::try_from(sender.clone().into_string())
            .expect("failed to convert sender address"),
        destination_chain,
        destination_address,
        payload_hash,
    };

    state::save_incoming_msg(store, cc_id, &msg).change_context(Error::InvalidStoreAccess)?;

    let (wasm_msg, events) = route(router, vec![msg.clone()])?;

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_event(AxelarnetGatewayEvent::ContractCalled { msg, payload }.into())
        .add_events(events))
}

// because the messages came from the router, we can assume they are already verified
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        state::save_outgoing_msg(store, msg.cc_id.clone(), msg.clone())
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

pub(crate) fn route_incoming_messages(
    store: &mut dyn Storage,
    router: &Router,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        let stored_msg = state::may_load_incoming_msg(store, &msg.cc_id)
            .change_context(Error::InvalidStoreAccess)?;

        match stored_msg {
            Some(message) if msg != &message => {
                Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
            }
            Some(_) => Ok(()),
            None => Err(report!(Error::MessageNotFound(msg.cc_id.clone()))),
        }?
    }

    let (wasm_msg, events) = route(router, msgs)?;

    Ok(Response::new().add_message(wasm_msg).add_events(events))
}

fn route(
    router: &Router,
    msgs: Vec<Message>,
) -> Result<(WasmMsg, impl IntoIterator<Item = Event>), Error> {
    Ok((
        router.route(msgs.clone()).ok_or(Error::RoutingFailed)?,
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

pub(crate) fn execute(
    store: &mut dyn Storage,
    api: &dyn Api,
    querier: QuerierWrapper,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, Error> {
    let msg = state::update_msg_status(store, cc_id.clone())
        .change_context(Error::MessageStatusUpdateFailed(cc_id))?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if payload_hash != msg.payload_hash {
        return Err(report!(Error::PayloadHashMismatch));
    }

    let config = state::load_config(store).change_context(Error::InvalidStoreAccess)?;
    if config.chain_name != msg.destination_chain {
        return Err(report!(Error::InvalidDestinationChain(
            msg.destination_chain
        )));
    }

    let destination_contract = api
        .addr_validate(&msg.destination_address)
        .change_context(Error::InvalidAddress(msg.destination_address.to_string()))?;

    let executable: AxelarExecutableClient =
        client::Client::new(querier, destination_contract).into();

    // Call the destination contract
    // Apps are required to expose AxelarExecutableMsg::Execute interface
    Ok(Response::new()
        .add_message(executable.execute(msg.cc_id.clone(), msg.source_address.clone(), payload))
        .add_event(AxelarnetGatewayEvent::MessageExecuted { msg }.into()))
}
