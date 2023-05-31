use cosmwasm_std::{Addr, Event, Uint256};

use crate::msg::Participant;

pub struct PollStarted {
    poll_id: String,
    participants: Vec<Participant>,
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute(
                "participants",
                format!(
                    "[{}]",
                    other
                        .participants
                        .iter()
                        .map(|p| format!("({},{})", p.address, p.weight))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
    }
}

pub struct VoteCast {
    poll_id: String,
    poll_finished: bool,
    sender: Addr,
    weight: Uint256,
}

impl From<VoteCast> for Event {
    fn from(other: VoteCast) -> Self {
        Event::new("vote_cast")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("poll_finished", other.poll_finished.to_string())
            .add_attribute("sender", other.sender)
            .add_attribute("weight", other.weight)
    }
}
