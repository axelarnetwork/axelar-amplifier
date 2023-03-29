use auth_vote::Poll;
use cosmwasm_std::{from_binary, to_binary, Event, WasmMsg};

use crate::msg::ActionMessage;

pub fn pending_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    // TODO: penalize non-voters
    build_event("PollExpired", poll, source_chain_name)
}

pub fn failed_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    build_event("PollFailed", poll, source_chain_name)
}

pub fn completed_poll_handler(
    poll: &Poll,
    source_chain_name: &str,
    router_address: &str,
) -> (WasmMsg, Event) {
    // TODO: rewards

    let router_message = connection_router::msg::ExecuteMsg::RouteMessage {
        message: poll.message.clone(),
    };

    let msg = WasmMsg::Execute {
        contract_addr: router_address.to_owned(),
        msg: to_binary(&router_message).unwrap(),
        funds: vec![],
    };

    let event = build_event("PollCompleted", poll, source_chain_name);

    (msg, event)
}

fn build_event(event_type: &str, poll: &Poll, source_chain_name: &str) -> Event {
    let ActionMessage::ConfirmGatewayTxs {
        from_nonce,
        to_nonce,
    } = from_binary(&poll.message).unwrap();

    Event::new(event_type)
        .add_attribute("chain", source_chain_name)
        .add_attribute("from_nonce", from_nonce)
        .add_attribute("to_nonce", to_nonce)
        .add_attribute("poll_id", poll.id)
}
