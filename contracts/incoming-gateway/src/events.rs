use cosmwasm_std::{Attribute, Event};

use crate::msg::Message;

impl From<Message> for Vec<Attribute> {
    fn from(other: Message) -> Self {
        vec![
            ("id", other.id),
            ("source_address", other.source_address),
            ("destination_address", other.destination_address),
            ("destination_domain", other.destination_domain),
            ("payload_hash", other.payload_hash.to_string()),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
}

pub enum GatewayEvent {
    MessageVerified { msg: Message},
    MessageVerificationFailed { msg: Message},
    MessageExecuted { msg: Message},
    MessageExecutionFailed { msg: Message},
}

fn make_event(event_name: &str, msg: Message) -> Event {
        let attrs: Vec<Attribute> = msg.into();
        Event::new(event_name).add_attributes(attrs)
}

impl From<GatewayEvent> for Event {
    fn from(other: GatewayEvent) -> Self {
        match other {
            GatewayEvent::MessageVerified { msg } => make_event("message_verified", msg),
            GatewayEvent::MessageExecuted { msg } => make_event("message_verified", msg),
            GatewayEvent::MessageVerificationFailed { msg } => make_event("message_verification_failed", msg),
            GatewayEvent::MessageExecutionFailed { msg } => make_event("message_execution_failed", msg),
        }
    }
}
