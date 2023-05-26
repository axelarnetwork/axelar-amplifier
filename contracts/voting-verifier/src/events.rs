use cosmwasm_std::Event;

pub struct PollStarted {
    messages: Vec<Message>,
    poll_id: String,
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        Event::new("poll_started")
            .add_attribute(
                "message_id",
                format!(
                    "[{}]",
                    other
                        .msgs
                        .iter()
                        .map(|m| m.id())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
            .add_attribute("poll_id", other.poll_id)
    }
}