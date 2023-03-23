use auth_vote::Poll;
use cosmwasm_std::{from_binary, Event};

use crate::msg::ActionMessage;

pub fn pending_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    let ActionMessage::ConfirmGatewayTxs {
        from_nonce,
        to_nonce,
    } = from_binary(&poll.message).unwrap();

    Event::new("PollExpired")
        .add_attribute("chain", source_chain_name)
        .add_attribute("from_nonce", from_nonce)
        .add_attribute("to_nonce", to_nonce)
        .add_attribute("poll_id", poll.id)
}

pub fn failed_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    let ActionMessage::ConfirmGatewayTxs {
        from_nonce,
        to_nonce,
    } = from_binary(&poll.message).unwrap();

    Event::new("PollFailed")
        .add_attribute("chain", source_chain_name)
        .add_attribute("from_nonce", from_nonce)
        .add_attribute("to_nonce", to_nonce)
        .add_attribute("poll_id", poll.id)
}

pub fn completed_poll_handler(poll: &Poll, source_chain_name: &str) -> Event {
    let ActionMessage::ConfirmGatewayTxs {
        from_nonce,
        to_nonce,
    } = from_binary(&poll.message).unwrap();

    Event::new("PollCompleted")
        .add_attribute("chain", source_chain_name)
        .add_attribute("from_nonce", from_nonce)
        .add_attribute("to_nonce", to_nonce)
        .add_attribute("poll_id", poll.id)
}
