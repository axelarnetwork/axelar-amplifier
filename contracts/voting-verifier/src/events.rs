use connection_router::events::make_message_event;
use connection_router::state::Message;
use cosmwasm_std::Event;

pub struct PollStarted {
    messages: Vec<Message>,
    poll_id: String,
}

impl From<PollStarted> for Vec<Event> {
    fn from(other: PollStarted) -> Self {
        let ev = Event::new("poll_started").add_attribute("poll_id", other.poll_id);
        let mut evs: Vec<Event> = other
            .messages
            .into_iter()
            .map(|m| make_message_event("message_added_to_poll", m))
            .collect();
        evs.push(ev);
        evs
    }
}
