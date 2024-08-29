use cosmwasm_std::Deps;
use itertools::Itertools;
use router_api::{CrossChainId, Message};

use crate::state::{self, ExecutableMessage};

pub fn routable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_routable_msg(deps.storage, &cc_id))
        .try_collect()
}

pub fn executable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_executable_msg(deps.storage, &cc_id))
        .try_collect()
}
