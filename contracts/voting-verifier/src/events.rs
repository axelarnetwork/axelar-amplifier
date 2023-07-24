use cosmwasm_std::{Addr, Event};

use axelar_wasm_std::voting::PollID;
use connection_router::state::Message;

use crate::state::Config;

impl From<Config> for Event {
    fn from(other: Config) -> Self {
        Event::new("instantiated")
            .add_attribute("service_name", other.service_name)
            .add_attribute("service_registry_contract", other.service_registry)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("voting_threshold", other.voting_threshold.to_string())
            .add_attribute("block_expiry", other.block_expiry.to_string())
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
    }
}

pub struct PollStarted {
    pub poll_id: PollID,
    pub source_gateway_address: String,
    pub confirmation_height: u64,
    pub messages: Vec<Message>,
    pub participants: Vec<Addr>,
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
            .add_attribute("participants", display_vector(&other.participants))
            .add_attribute("messages", display_vector(&other.messages))
    }
}

pub struct Voted {
    pub poll_id: PollID,
    pub voter: Addr,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("voter", other.voter)
    }
}

pub struct PollEnded<'a> {
    pub poll_id: PollID,
    pub results: &'a Vec<bool>,
}

impl From<PollEnded<'_>> for Event {
    fn from(other: PollEnded) -> Self {
        Event::new("poll_ended")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("voter", display_vector(other.results))
    }
}

fn display_vector<T>(v: &[T]) -> String
where
    T: std::fmt::Display,
{
    format!(
        "[{}]",
        v.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}
