use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::voting::{PollId, Vote, WeightedPoll};
use axelar_wasm_std::{counter, nonempty, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use event_verifier_api::EventToVerify;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a poll expires
}

#[cw_serde]
pub struct EventInPoll {
    pub event: EventToVerify, // content is stored for migration purposes in case the hash changes
    pub poll_id: PollId,
    pub index_in_poll: u32,
}

impl EventInPoll {
    pub fn new(event: EventToVerify, poll_id: PollId, index_in_poll: usize) -> Self {
        Self {
            event,
            poll_id,
            index_in_poll: index_in_poll.try_into().unwrap(),
        }
    }
}

pub const POLL_ID: counter::Counter<PollId> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollId, WeightedPoll> = Map::new("polls");

type VerifierAddr = String;
pub const VOTES: Map<(PollId, VerifierAddr), Vec<Vote>> = Map::new("votes");

pub const CONFIG: Item<Config> = Item::new("config");

/// A multi-index that indexes an event by (PollID, index in poll) pair. The primary key of the underlying
/// map is the hash of the event (typed as Hash). This allows looking up an EventToVerify by its hash,
/// or by a (PollID, index in poll) pair. The PollID is stored as a String
pub struct PollEventsIndex<'a>(MultiIndex<'a, (String, u32), EventInPoll, &'a Hash>);

impl<'a> PollEventsIndex<'a> {
    fn new(
        idx_fn: fn(&[u8], &EventInPoll) -> (String, u32),
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
            .collect::<Result<Vec<([u8; 32], EventInPoll)>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, event_in_poll)] => Ok(Some(event_in_poll.event.to_owned())),
            _ => panic!("More than one event for poll_id and index_in_poll"),
        }
    }

    pub fn load_events(
        &self,
        storage: &dyn Storage,
        poll_id: PollId,
    ) -> StdResult<Vec<EventToVerify>> {
        poll_events()
            .idx
            .0
            .sub_prefix(poll_id.to_string())
            .range(storage, None, None, Order::Ascending)
            .map(|item| item.map(|(_, event_in_poll)| event_in_poll.event))
            .collect::<StdResult<Vec<_>>>()
    }
}

const POLL_EVENTS_PKEY_NAMESPACE: &str = "poll_events";
const POLL_EVENTS_IDX_NAMESPACE: &str = "poll_events_idx";

pub fn poll_events<'a>() -> IndexedMap<&'a Hash, EventInPoll, PollEventsIndex<'a>> {
    IndexedMap::new(
        POLL_EVENTS_PKEY_NAMESPACE,
        PollEventsIndex::new(
            |_pk: &[u8], d: &EventInPoll| (d.poll_id.to_string(), d.index_in_poll),
            POLL_EVENTS_PKEY_NAMESPACE,
            POLL_EVENTS_IDX_NAMESPACE,
        ),
    )
}

impl IndexList<EventInPoll> for PollEventsIndex<'_> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<EventInPoll>> + '_> {
        let v: Vec<&dyn Index<EventInPoll>> = vec![&self.0];
        Box::new(v.into_iter())
    }
}
