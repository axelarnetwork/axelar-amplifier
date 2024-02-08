use crate::error::ContractError;
use crate::state::OUTGOING_MESSAGES;
use connection_router::state::CrossChainId;
use cosmwasm_std::{to_binary, Binary, Deps};
use error_stack::{Result, ResultExt};

pub fn get_messages(
    deps: Deps,
    cross_chain_ids: Vec<CrossChainId>,
) -> Result<Binary, ContractError> {
    let msgs = cross_chain_ids
        .into_iter()
        .map(|id| {
            OUTGOING_MESSAGES
                .load(deps.storage, id.clone())
                .change_context(ContractError::LoadOutgoingMessage)
                .attach_printable(id.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    to_binary(&msgs).change_context(ContractError::LoadOutgoingMessage)
}
