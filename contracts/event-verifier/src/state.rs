use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::voting::{PollId, Vote, WeightedPoll};
use axelar_wasm_std::{counter, nonempty, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};
use router_api::ChainName;
use crate::msg::EventToVerify;

use crate::error::ContractError;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
    pub msg_id_format: MessageIdFormat,
    pub address_format: AddressFormat,
}

#[cw_serde]
pub enum Poll {
    Events(WeightedPoll),
}

impl Poll {
    pub fn try_map<F, E>(self, func: F) -> Result<Self, E>
    where
        F: FnOnce(WeightedPoll) -> Result<WeightedPoll, E>,
        E: From<ContractError>,
    {
        match self {
            Poll::Events(poll) => Ok(Poll::Events(func(poll)?)),
        }
    }

    pub fn weighted_poll(self) -> WeightedPoll {
        match self {
            Poll::Events(poll) => poll,
        }
    }
}

#[cw_serde]
pub struct PollContent<T> {
    pub content: T, // content is stored for migration purposes in case the hash changes
    pub poll_id: PollId,
    pub index_in_poll: u32,
}



impl PollContent<EventToVerify> {
    pub fn new(event: EventToVerify, poll_id: PollId, index_in_poll: usize) -> Self {
        Self {
            content: event,
            poll_id,
            index_in_poll: index_in_poll.try_into().unwrap(),
        }
    }
}



pub const POLL_ID: counter::Counter<PollId> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollId, Poll> = Map::new("polls");

type VerifierAddr = String;
pub const VOTES: Map<(PollId, VerifierAddr), Vec<Vote>> = Map::new("votes");

pub const CONFIG: Item<Config> = Item::new("config");



/// A multi-index that indexes an event by (PollID, index in poll) pair. The primary key of the underlying
/// map is the hash of the event (typed as Hash). This allows looking up an EventToVerify by its hash,
/// or by a (PollID, index in poll) pair. The PollID is stored as a String
pub struct PollEventsIndex<'a>(MultiIndex<'a, (String, u32), PollContent<EventToVerify>, &'a Hash>);

impl<'a> PollEventsIndex<'a> {
    fn new(
        idx_fn: fn(&[u8], &PollContent<EventToVerify>) -> (String, u32),
        pk_namespace: &'a str,
        idx_namespace: &'static str,
    ) -> Self {
        PollEventsIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn load_event(
        &self,
        storage: &dyn Storage,
        poll_id: PollId,
        index_in_poll: u32,
    ) -> StdResult<Option<EventToVerify>> {
        match self
            .0
            .prefix((poll_id.to_string(), index_in_poll))
            .range(storage, None, None, Order::Ascending)
            .collect::<Result<Vec<([u8; 32], PollContent<EventToVerify>)>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, content)] => Ok(Some(content.content.to_owned())),
            _ => panic!("More than one event for poll_id and index_in_poll"),
        }
    }

    pub fn load_events(&self, storage: &dyn Storage, poll_id: PollId) -> StdResult<Vec<EventToVerify>> {
        poll_events()
            .idx
            .0
            .sub_prefix(poll_id.to_string())
            .range(storage, None, None, Order::Ascending)
            .map(|item| item.map(|(_, poll_content)| poll_content.content))
            .collect::<StdResult<Vec<_>>>()
    }
}

const POLL_EVENTS_PKEY_NAMESPACE: &str = "poll_events";
const POLL_EVENTS_IDX_NAMESPACE: &str = "poll_events_idx";

pub fn poll_events<'a>() -> IndexedMap<&'a Hash, PollContent<EventToVerify>, PollEventsIndex<'a>> {
    IndexedMap::new(
        POLL_EVENTS_PKEY_NAMESPACE,
        PollEventsIndex::new(
            |_pk: &[u8], d: &PollContent<EventToVerify>| (d.poll_id.to_string(), d.index_in_poll),
            POLL_EVENTS_PKEY_NAMESPACE,
            POLL_EVENTS_IDX_NAMESPACE,
        ),
    )
}

impl IndexList<PollContent<EventToVerify>> for PollEventsIndex<'_> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<PollContent<EventToVerify>>> + '_> {
        let v: Vec<&dyn Index<PollContent<EventToVerify>>> = vec![&self.0];
        Box::new(v.into_iter())
    }
}


