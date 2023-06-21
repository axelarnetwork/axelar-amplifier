use connection_router::events::make_message_event;
use connection_router::state::Message;
use cosmwasm_std::{Addr, Event};

pub struct PollStarted {
    messages: Vec<Message>,
    poll_id: String,
    participants: Vec<Addr>,
}

impl From<PollStarted> for Vec<Event> {
    fn from(other: PollStarted) -> Self {
        let ev = Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute(
                "participants",
                format!(
                    "[{}]",
                    other
                        .participants
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        let mut evs: Vec<Event> = other
            .messages
            .into_iter()
            .map(|m| make_message_event("message_added_to_poll", m))
            .collect();
        evs.push(ev);
        evs
    }
}
