use connection_router::state::{CrossChainId, NewMessage};
use cosmwasm_std::{Deps, StdResult};

use crate::error::ContractError;
use crate::state::VERIFIED_MESSAGES;

pub fn verification_statuses(
    deps: Deps,
    messages: Vec<NewMessage>,
) -> StdResult<Vec<(CrossChainId, bool)>> {
    messages
        .into_iter()
        .map(|message| {
            is_message_verified(deps, &message).map(|verified| (message.cc_id, verified))
        })
        .collect::<Result<Vec<(_, _)>, _>>()
        .map_err(Into::into)
}

pub fn is_message_verified(deps: Deps, message: &NewMessage) -> Result<bool, ContractError> {
    match VERIFIED_MESSAGES.may_load(deps.storage, &message.cc_id)? {
        Some(stored) if stored != *message => {
            Err(ContractError::MessageMismatch(message.cc_id.to_string()))
        }
        Some(_) => Ok(true),
        None => Ok(false),
    }
}
