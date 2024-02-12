use connection_router::state::{CrossChainId, Message};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};

#[cw_serde]
pub(crate) struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub(crate) fn save_config(storage: &mut dyn Storage, value: &Config) -> Result<(), Error> {
    CONFIG
        .save(storage, value)
        .change_context(Error::SaveValue(CONFIG_NAME))
}
pub(crate) fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .load(storage)
        .change_context(Error::LoadValue(CONFIG_NAME))
}

pub(crate) fn save_outgoing_msg(
    storage: &mut dyn Storage,
    key: CrossChainId,
    value: &Message,
) -> Result<(), Error> {
    OUTGOING_MESSAGES
        .save(storage, key, value)
        .change_context(Error::SaveValue(OUTGOING_MESSAGES_NAME))
}
pub(crate) fn may_load_outgoing_msg(
    storage: &dyn Storage,
    id: CrossChainId,
) -> Result<Option<Message>, Error> {
    OUTGOING_MESSAGES
        .may_load(storage, id.clone())
        .change_context(Error::Parse(OUTGOING_MESSAGES_NAME))
        .attach_printable(id.to_string())
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("failed to save {0}")]
    SaveValue(&'static str),
    #[error("failed to load {0}")]
    LoadValue(&'static str),
    #[error("failed to parse key for {0}")]
    Parse(&'static str),
}

const CONFIG_NAME: &str = "config";
const CONFIG: Item<Config> = Item::new(CONFIG_NAME);
const OUTGOING_MESSAGES_NAME: &str = "outgoing_messages";
const OUTGOING_MESSAGES: Map<CrossChainId, Message> = Map::new(OUTGOING_MESSAGES_NAME);
