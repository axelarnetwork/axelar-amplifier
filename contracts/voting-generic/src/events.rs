use cosmwasm_std::Event;

pub struct PollStarted {
    poll_id: String,
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        Event::new("poll_started").add_attribute("poll_id", other.poll_id)
    }
}

pub struct VoteCast {
    poll_id: String,
    poll_finished: bool,
}

impl From<VoteCast> for Event {
    fn from(other: VoteCast) -> Self {
        Event::new("vote_cast")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("poll_finished", other.poll_finished)
    }
}
