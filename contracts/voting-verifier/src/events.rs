use crate::msg::Message;
use cosmwasm_std::Attribute;
use cosmwasm_std::Event;

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
pub struct PollStarted {
    messages: Vec<Message>,
    poll_id: String,
}

impl From<PollStarted> for Vec<Event> {
    fn from(other: PollStarted) -> Self {
        let ev = Event::new("poll_started").add_attribute("poll_id", other.poll_id);
        let mut evs: Vec<Event> = other
            .messages
            .iter()
            .map(|m| {
                let attrs: Vec<Attribute> = m.clone().into();
                Event::new("message_added_to_poll").add_attributes(attrs)
            })
            .collect();
        evs.push(ev);
        evs
    }
}
