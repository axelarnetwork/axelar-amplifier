use connection_router_api::{CrossChainId, Message};
use cosmwasm_std::Storage;
use error_stack::{Result, ResultExt};
use itertools::Itertools;

use crate::contract::Error;
use crate::state;

pub fn get_outgoing_messages(
    storage: &dyn Storage,
    cross_chain_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, Error> {
    cross_chain_ids
        .into_iter()
        .filter_map(|id| state::may_load_outgoing_msg(storage, id).transpose())
        .try_collect()
        .change_context(Error::InvalidStoreAccess)
}
