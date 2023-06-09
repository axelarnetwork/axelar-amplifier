use connection_router::state::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Deps, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
pub enum MessageStatus {
    Received, // received but not yet verified (incoming messages)
    Verified, // verified but not yet sent to the router (incoming messages)
    Executed, // verified and sent to the router (incoming messages)
    Sent,     // received from the router (outgoing messages)
}

const MESSAGES_PKEY: &str = "messages";

// messages maps sha256 digest of the message to the message itself, along with current status
// A hash of the contents is used instead of the ID, because prior to verification, two different
// messages could have the same ID.
pub fn messages<'a>() -> IndexedMap<'a, String, (Message, MessageStatus), MessageIndexes<'a>> {
    return IndexedMap::new(
        MESSAGES_PKEY,
        MessageIndexes {
            id: MessageIDIndex::new(
                |_pk: &[u8], (m, _): &(Message, MessageStatus)| m.id(),
                MESSAGES_PKEY,
                "message_ids",
            ),
        },
    );
}

// index messages by ID. Primary key of messages is sha256 digest of the message
pub struct MessageIndexes<'a> {
    pub id: MessageIDIndex<'a>,
}

pub struct MessageIDIndex<'a>(MultiIndex<'a, String, (Message, MessageStatus), String>);

impl<'a> MessageIDIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &(Message, MessageStatus)) -> String,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        MessageIDIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn find_messages(&self, deps: &Deps, id: &str) -> StdResult<Vec<(Message, MessageStatus)>> {
        let matching_messages = self
            .0
            .prefix(id.to_owned())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(matching_messages.iter().map(|(_, p)| p.clone()).collect())
    }
}

impl<'a> IndexList<(Message, MessageStatus)> for MessageIndexes<'a> {
    fn get_indexes(
        &'_ self,
    ) -> Box<dyn Iterator<Item = &'_ dyn Index<(Message, MessageStatus)>> + '_> {
        let v: Vec<&dyn Index<(Message, MessageStatus)>> = vec![&self.id.0];
        Box::new(v.into_iter())
    }
}

// data to store for use in submessage reply
#[cw_serde]
pub struct CallbackCache {
    pub messages: Vec<(Message, MessageStatus)>,
}
pub const CACHED: Item<CallbackCache> = Item::new("callback_cache");
