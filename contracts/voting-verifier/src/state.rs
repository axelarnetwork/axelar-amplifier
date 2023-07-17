use std::array::TryFromSliceError;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult};
use cw_storage_plus::{IntKey, Item, Key, KeyDeserialize, Map, Prefixer, PrimaryKey};

use axelar_wasm_std::{counter, hash, voting::WeightedPoll, Threshold};

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: String,
    pub source_gateway_address: String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u8,
}

#[cw_serde]
pub struct PendingMessageID {
    pub poll_id: u64,
    pub index: u64,
}

impl<'a> PrimaryKey<'a> for PendingMessageID {
    type Prefix = u64;
    type SubPrefix = u64;
    type Suffix = ();
    type SuperSuffix = ();

    fn key(&self) -> Vec<Key> {
        vec![
            Key::Val64(self.poll_id.to_cw_bytes()),
            Key::Val64(self.index.to_cw_bytes()),
        ]
    }
}

impl KeyDeserialize for PendingMessageID {
    type Output = Self;

    fn from_vec(mut value: Vec<u8>) -> StdResult<Self> {
        if value.len() != 16 {
            return Err(StdError::invalid_data_size(16, value.len()));
        }

        let poll_id = u64_from_bytes(&value.split_off(8))?;
        let index = u64_from_bytes(&value)?;

        Ok(Self { poll_id, index })
    }
}

impl KeyDeserialize for &PendingMessageID {
    type Output = PendingMessageID;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Self::Output::from_vec(value)
    }
}

fn u64_from_bytes(bytes: &[u8]) -> StdResult<u64> {
    Ok(u64::from_cw_bytes(bytes.try_into().map_err(
        |e: TryFromSliceError| StdError::generic_err(e.to_string()),
    )?))
}

pub const POLL_ID: counter::Counter<u64> = counter::Counter::new("poll_id");

pub const POLLS: Map<u64, WeightedPoll> = Map::new("polls");

pub const PENDING_MESSAGES: Map<&PendingMessageID, hash::Hash> = Map::new("pending_messages");

pub const VERIFIED_MESSAGES: Map<&hash::Hash, ()> = Map::new("verified_messages");

pub const CONFIG: Item<Config> = Item::new("config");
