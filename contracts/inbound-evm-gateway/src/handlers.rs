use auth_vote::Poll;
use cosmwasm_std::{from_binary, Event};

use crate::msg::ActionMessage;

pub fn pending_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    // TODO: penalize non-voters
    build_event("PollExpired", poll, source_chain_name)
}

pub fn failed_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    build_event("PollFailed", poll, source_chain_name)
}

pub fn completed_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    // TODO: rewards

    // TODO: message for router
    build_event("PollCompleted", poll, source_chain_name)
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
