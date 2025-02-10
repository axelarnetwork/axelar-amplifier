use cosmwasm_std::Storage;
use itertools::Itertools;
use router_api::{ChainName, CrossChainId, Message};

use crate::msg::ExecutableMessage;
use crate::state;

pub fn routable_messages(
    storage: &dyn Storage,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_routable_msg(storage, &cc_id))
        .try_collect()
}

pub fn executable_messages(
    storage: &dyn Storage,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, state::Error> {
    let results: Vec<_> = cc_ids
        .into_iter()
        .map(|cc_id| state::load_executable_msg(storage, &cc_id))
        .try_collect()?;

    Ok(results.into_iter().map(Into::into).collect())
}

pub fn chain_name(storage: &dyn Storage) -> ChainName {
    state::load_config(storage).chain_name
}
