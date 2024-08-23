use axelar_wasm_std::error::accumulate_errs;
use cosmwasm_std::Deps;
use error_stack::Result;
use router_api::{CrossChainId, Message};

use crate::state::{self, ExecutableMessage};

pub fn routable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_routable_msg(deps.storage, &cc_id))
        .fold(Ok(vec![]), accumulate_errs)
}

pub fn executable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, state::Error> {
    cc_ids
        .into_iter()
        .map(|cc_id| state::load_executable_msg(deps.storage, &cc_id))
        .fold(Ok(vec![]), accumulate_errs)
}
