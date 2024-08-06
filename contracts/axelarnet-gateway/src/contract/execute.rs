use axelar_wasm_std::nonempty;
use cosmwasm_std::{to_json_binary, Addr, Api, HexBinary, Response, Storage, WasmMsg};
use error_stack::{report, Result, ResultExt};
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::contract::Error;
use crate::events::AxelarnetGatewayEvent;
use crate::msg::AxelarExecutableExecuteMsg;
use crate::state::{self};

// TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it. Use a placeholder in the meantime.
const PLACEHOLDER_TX_HASH: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) fn call_contract(
    store: &mut dyn Storage,
    router: &Router,
    chain_name: ChainName,
    sender: Addr,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let counter =
        state::increment_message_counter(store).change_context(Error::InvalidStoreAccess)?;

    let cc_id = CrossChainId {
        source_chain: chain_name.into(),
        message_id: nonempty::String::try_from(format!("{0}-{1}", PLACEHOLDER_TX_HASH, counter))
            .change_context(Error::MessageIdConstructionFailed)?,
    };

    let payload_hash = Keccak256::digest(payload.as_slice()).into();

    let msg = Message {
        cc_id: cc_id.clone(),
        source_address: Address::try_from(sender.clone().into_string())
            .change_context(Error::InvalidSender(sender))?,
        destination_chain,
        destination_address,
        payload_hash,
    };

    state::save_incoming_msg(store, cc_id, &msg).change_context(Error::InvalidStoreAccess)?;

    let wasm_msg = router
        .route(vec![msg.clone()])
        .ok_or(Error::RoutingFailed)?;

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_event(AxelarnetGatewayEvent::ContractCalled { msg, payload }.into()))
}

// because the messages came from the router, we can assume they are already verified
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        state::save_outgoing_message(store, msg.cc_id.clone(), msg.clone())
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
            .change_context(Error::MessageNotFound(msg.cc_id.clone()))?;

        match stored_msg {
            Some(message) if msg != &message => {
                Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
            }
            _ => Ok(()),
        }?
    }

    let wasm_msg = router.route(msgs.clone()).ok_or(Error::RoutingFailed)?;
    let events = msgs
        .into_iter()
        .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into());

    Ok(Response::new().add_message(wasm_msg).add_events(events))
}

pub(crate) fn execute(
    store: &mut dyn Storage,
    api: &dyn Api,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, Error> {
    let msg = state::update_message_status(store, cc_id.clone())
        .change_context(Error::MessageStatusUpdateFailed(cc_id))?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if payload_hash != msg.payload_hash {
        return Err(report!(Error::PayloadHashMismatch));
    }

    let destination_contract = api
        .addr_validate(&msg.destination_address)
        .change_context(Error::InvalidAddress(msg.destination_address.to_string()))?;

    // Apps are required to expose AxelarExecutableExecuteMsg::Execute interface
    let execute_msg = AxelarExecutableExecuteMsg::Execute {
        cc_id: msg.cc_id.clone(),
        source_address: msg.source_address.clone(),
        destination_chain: msg.destination_chain.clone(),
        destination_address: msg.destination_address.clone(),
        payload,
    };

    let wasm_msg = WasmMsg::Execute {
        contract_addr: destination_contract.to_string(),
        msg: to_json_binary(&execute_msg).change_context(Error::SerializeWasmMsg)?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_event(AxelarnetGatewayEvent::MessageExecuted { msg }.into()))
}
