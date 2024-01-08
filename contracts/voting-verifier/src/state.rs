use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{
    counter,
    hash::Hash,
    nonempty,
    operators::Operators,
    voting::{PollId, WeightedPoll},
    MajorityThreshold,
};
use connection_router::state::{ChainName, Message};

use crate::error::ContractError;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
}

#[cw_serde]
pub enum Poll {
    Messages(WeightedPoll),
    ConfirmWorkerSet(WeightedPoll),
}

impl Poll {
    pub fn try_map<F, E>(self, func: F) -> Result<Self, E>
    where
        F: FnOnce(WeightedPoll) -> Result<WeightedPoll, E>,
        E: From<ContractError>,
    {
        match self {
            Poll::Messages(poll) => Ok(Poll::Messages(func(poll)?)),
            Poll::ConfirmWorkerSet(poll) => Ok(Poll::ConfirmWorkerSet(func(poll)?)),
        }
    }
}

#[cw_serde]
pub struct PollContent<T> {
    pub content: T, // content is stored for migration purposes in case the hash changes
    pub poll_id: PollId,
    pub index_in_poll: u32,
}

impl PollContent<Message> {
    pub fn new(message: Message, poll_id: PollId, index_in_poll: usize) -> Self {
        Self {
            content: message,
            poll_id,
            index_in_poll: index_in_poll.try_into().unwrap(),
        }
    }
}

impl PollContent<Operators> {
    pub fn new(operators: Operators, poll_id: PollId) -> Self {
        Self {
            content: operators,
            poll_id,
            index_in_poll: 0,
        }
    }
}

pub const POLL_ID: counter::Counter<PollId> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollId, Poll> = Map::new("polls");

pub const POLL_MESSAGES: Map<&Hash, PollContent<Message>> = Map::new("poll_messages");

pub const CONFIG: Item<Config> = Item::new("config");

pub const POLL_WORKER_SETS: Map<&Hash, PollContent<Operators>> = Map::new("poll_worker_sets");
