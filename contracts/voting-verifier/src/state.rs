use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use axelar_wasm_std::{
    counter,
    voting::{PollID, WeightedPoll},
    Threshold,
};
use connection_router::state::Message;
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

pub const POLL_ID: counter::Counter<PollID> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollID, WeightedPoll> = Map::new("polls");

#[cw_serde]
pub struct TaggedMessage {
    msg: Message,
    poll_id: PollID,
    index_in_poll: u32,
}

impl TaggedMessage {
    pub fn new(msg: Message, poll_id: PollID, index_in_poll: u32) -> Self {
        TaggedMessage {
            msg,
            poll_id,
            index_in_poll,
        }
    }

    pub fn poll_id(&self) -> PollID {
        self.poll_id
    }

    pub fn index_in_poll(&self) -> u32 {
        self.index_in_poll
    }

    pub fn message(&self) -> Message {
        self.msg.clone()
    }
}

pub struct PollIndexes<'a> {
    pub polls: PollIndex<'a>,
}
pub struct PollIndex<'a>(MultiIndex<'a, (PollID, u32), TaggedMessage, MessageID>);
impl<'a> PollIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &TaggedMessage) -> (PollID, u32),
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        PollIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }
    pub fn find_message(
        &self,
        deps: &DepsMut,
        poll_id: &PollID,
        idx: u32,
    ) -> StdResult<Option<Message>> {
        let mut matching_messages = self
            .0
            .prefix((*poll_id, idx))
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?;
        if matching_messages.len() > 1 {
            panic!("More than one message for poll id and index")
        }
        Ok(matching_messages
            .pop()
            .map(|(_, TaggedMessage { msg, .. })| msg))
    }
}
const MESSAGES_PKEY: &str = "messages";

pub fn messages<'a>() -> IndexedMap<'a, MessageID, TaggedMessage, PollIndexes<'a>> {
    return IndexedMap::new(
        MESSAGES_PKEY,
        PollIndexes {
            polls: PollIndex::new(
                |_pk: &[u8], d: &TaggedMessage| (d.poll_id, d.index_in_poll),
                MESSAGES_PKEY,
                "polls",
            ),
        },
    );
}

impl<'a> IndexList<TaggedMessage> for PollIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<TaggedMessage>> + '_> {
        let v: Vec<&dyn Index<TaggedMessage>> = vec![&self.polls.0];
        Box::new(v.into_iter())
    }
}

pub const CONFIG: Item<Config> = Item::new("config");
