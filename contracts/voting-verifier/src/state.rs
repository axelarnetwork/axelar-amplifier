use std::array::TryFromSliceError;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult};
use cw_storage_plus::{IntKey, Item, Key, KeyDeserialize, Map, PrimaryKey};

use axelar_wasm_std::{counter, hash, voting::WeightedPoll, Threshold};
use connection_router::types::ChainName;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: String,
    pub source_gateway_address: String,
    pub chain: ChainName,
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
    type SubPrefix = ();
    type Suffix = u64;
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
        if value.len() != 18 {
            return Err(StdError::invalid_data_size(18, value.len()));
        }

        let mut value = value.split_off(2);
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockStorage;
    use cosmwasm_std::Order;

    use super::*;

    #[test]
    fn can_use_prefix_to_query_by_poll_id() {
        let mut store = MockStorage::new();

        let message_len = 1000;

        let poll_4: Vec<hash::Hash> = (0..message_len)
            .map(|i| hash::Hash::new([i as u8; 32]))
            .collect();
        let poll_5: Vec<hash::Hash> = (0..message_len)
            .map(|i| hash::Hash::new([(i + message_len) as u8; 32]))
            .collect();

        for i in 0..message_len {
            PENDING_MESSAGES
                .save(
                    &mut store,
                    &PendingMessageID {
                        poll_id: 4,
                        index: i,
                    },
                    poll_4.get(i as usize).unwrap(),
                )
                .unwrap();
            PENDING_MESSAGES
                .save(
                    &mut store,
                    &PendingMessageID {
                        poll_id: 5,
                        index: i,
                    },
                    poll_5.get(i as usize).unwrap(),
                )
                .unwrap();
        }

        // query all
        let all: StdResult<Vec<_>> = PENDING_MESSAGES
            .range(&store, None, None, Order::Ascending)
            .collect();
        let all = all.unwrap();
        assert_eq!(message_len * 2, all.len() as u64);

        // // query by poll_id
        let prefix = PENDING_MESSAGES.prefix(5);
        let msgs: StdResult<Vec<_>> = prefix.range(&store, None, None, Order::Ascending).collect();

        let msgs = msgs.unwrap();
        let expected: Vec<(u64, hash::Hash)> = (0..message_len)
            .map(|i| (i, poll_5.get(i as usize).unwrap().clone()))
            .collect();
        assert_eq!(msgs, expected);
    }
}
