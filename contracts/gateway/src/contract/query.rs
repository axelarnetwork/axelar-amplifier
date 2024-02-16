use crate::contract::Error;
use crate::state;
use connection_router::state::CrossChainId;
use connection_router::Message;
use cosmwasm_std::Storage;
use error_stack::{Result, ResultExt};
use itertools::Itertools;

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
