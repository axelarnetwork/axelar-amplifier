use connection_router::state::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub const OUTGOING_MESSAGES: Map<String, Message> = Map::new("outgoing_messages");

// data to store for use in submessage reply
#[cw_serde]
pub struct CallbackCache {
    pub messages: Vec<Message>,
}
pub const CACHED: Item<CallbackCache> = Item::new("callback_cache");
