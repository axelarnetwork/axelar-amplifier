use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{
    counter, nonempty,
    operators::Operators,
    voting::{PollID, WeightedPoll},
    Threshold,
};
use connection_router::state::{ChainName, CrossChainId, Message};

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
}

#[cw_serde]
pub enum Poll {
    Messages(WeightedPoll),
    ConfirmWorkerSet(WeightedPoll),
}

pub const POLL_ID: counter::Counter<PollID> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollID, Poll> = Map::new("polls");

pub const PENDING_MESSAGES: Map<PollID, Vec<Message>> = Map::new("pending_messages");

pub const VERIFIED_MESSAGES: Map<&CrossChainId, Message> = Map::new("verified_messages");

pub const CONFIG: Item<Config> = Item::new("config");

type OperatorsHash = Vec<u8>;
pub const CONFIRMED_WORKER_SETS: Map<OperatorsHash, ()> = Map::new("confirmed_worker_sets");

pub const PENDING_WORKER_SETS: Map<PollID, Operators> = Map::new("pending_worker_sets");
