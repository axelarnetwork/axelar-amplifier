use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{
    counter, nonempty,
    operators::Operators,
    voting::{self, PollID, WeightedPoll},
    Threshold,
};
use connection_router::state::{ChainName, CrossChainId, Message};

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

impl voting::Poll for Poll {
    type E = ContractError;

    fn finish(self, block_height: u64) -> Result<Self, ContractError> {
        self.try_map(|poll| poll.finish(block_height).map_err(ContractError::from))
    }

    fn result(&self) -> voting::PollResult {
        match self {
            Poll::Messages(poll) | Poll::ConfirmWorkerSet(poll) => poll.result(),
        }
    }

    fn cast_vote(
        self,
        block_height: u64,
        sender: &Addr,
        votes: Vec<bool>,
    ) -> Result<Self, ContractError> {
        self.try_map(|poll| {
            poll.cast_vote(block_height, sender, votes)
                .map_err(ContractError::from)
        })
    }
}

impl Poll {
    fn try_map<F, E>(self, func: F) -> Result<Self, E>
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

pub const POLL_ID: counter::Counter<PollID> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollID, Poll> = Map::new("polls");

pub const PENDING_MESSAGES: Map<PollID, Vec<Message>> = Map::new("pending_messages");

pub const VERIFIED_MESSAGES: Map<&CrossChainId, Message> = Map::new("verified_messages");

pub const CONFIG: Item<Config> = Item::new("config");

type OperatorsHash = Vec<u8>;
pub const CONFIRMED_WORKER_SETS: Map<OperatorsHash, ()> = Map::new("confirmed_worker_sets");

pub const PENDING_WORKER_SETS: Map<PollID, Operators> = Map::new("pending_worker_sets");
