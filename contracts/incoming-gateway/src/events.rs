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
        .iter()
        .map(|a| {
            let attr: Attribute = a.clone().into();
            attr
        })
        .collect()
    }
}

pub struct MessageVerified {
    pub msg: Message,
}

impl From<MessageVerified> for Event {
    fn from(other: MessageVerified) -> Self {
        let attrs: Vec<Attribute> = other.msg.into();
        Event::new("message_verified").add_attributes(attrs)
    }
}
pub struct MessageVerificationFailed {
    pub msg: Message,
}

impl From<MessageVerificationFailed> for Event {
    fn from(other: MessageVerificationFailed) -> Self {
        let attrs: Vec<Attribute> = other.msg.into();
        Event::new("message_verification_failed").add_attributes(attrs)
    }
}

pub struct MessageExecuted {
    pub msg: Message,
}

impl From<MessageExecuted> for Event {
    fn from(other: MessageExecuted) -> Self {
        let attrs: Vec<Attribute> = other.msg.into();
        Event::new("message_executed").add_attributes(attrs)
    }
}

pub struct MessageExecutionFailed {
    pub msg: Message,
}

impl From<MessageExecutionFailed> for Event {
    fn from(other: MessageExecutionFailed) -> Self {
        let attrs: Vec<Attribute> = other.msg.into();
        Event::new("message_execution_failed").add_attributes(attrs)
    }
}
