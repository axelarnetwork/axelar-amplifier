use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{counter, hash, voting::WeightedPoll, Threshold};
use connection_router::types::MessageID;

#[cw_serde]
pub struct Config {
    pub service_registry: Addr,
    pub service_name: String,
    pub source_gateway_address: String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
}

pub const POLL_ID: counter::Counter<u64> = counter::Counter::new("poll_id");

pub const POLLS: Map<u64, WeightedPoll> = Map::new("polls");

pub const PENDING_MESSAGES: Map<u64, Vec<hash::Hash>> = Map::new("pending_messages");

pub const VERIFIED_MESSAGES: Map<&MessageID, hash::Hash> = Map::new("verified_messages");

pub const CONFIG: Item<Config> = Item::new("config");
