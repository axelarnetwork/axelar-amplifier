use cosmwasm_std::Event;

use crate::msg::Message;

pub struct MessagesVerified {
    pub msgs: Vec<Message>,
}

impl From<MessagesVerified> for Event {
    fn from(other: MessagesVerified) -> Self {
        Event::new("messages_verified").add_attribute(
            "message_id",
            format!(
                "[{}]",
                other
                    .msgs
                    .iter()
                    .map(|m| m.id.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        )
    }
}

pub struct MessagesExecuted {
    pub msgs: Vec<Message>,
}

impl From<MessagesExecuted> for Event {
    fn from(other: MessagesExecuted) -> Self {
        Event::new("messages_executed").add_attribute(
            "message_id",
            format!(
                "[{}]",
                other
                    .msgs
                    .iter()
                    .map(|m| m.id.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        )
    }
}