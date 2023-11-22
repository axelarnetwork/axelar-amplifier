use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{
    counter, nonempty,
    operators::{Operators, OperatorsHash},
    voting::{PollID, WeightedPoll},
    Threshold,
};
use connection_router::state::{ChainName, Message, MessageHash};

use crate::error::ContractError;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: Threshold,
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
pub struct PollMessage {
    pub msg: Message, // message is stored for migration purposes in case the hash changes
    pub poll_id: PollID,
    pub index_in_poll: usize,
}

impl PollMessage {
    pub fn new(msg: Message, poll_id: PollID, index_in_poll: usize) -> Self {
        Self {
            msg,
            poll_id,
            index_in_poll,
        }
    }
}

#[cw_serde]
pub struct PollWorkerSet {
    pub operators: Operators, // operators are stored for migration purposes in case the hash changes
    pub poll_id: PollID,
}

impl PollWorkerSet {
    pub fn new(operators: Operators, poll_id: PollID) -> Self {
        Self { operators, poll_id }
    }
}

pub const POLL_ID: counter::Counter<PollID> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollID, Poll> = Map::new("polls");

pub const POLL_MESSAGES: Map<&MessageHash, PollMessage> = Map::new("poll_messages");

pub const CONFIG: Item<Config> = Item::new("config");

pub const POLL_WORKER_SETS: Map<&OperatorsHash, PollWorkerSet> = Map::new("poll_worker_sets");
