use cosmwasm_std::{Deps, StdResult};

use connection_router::state::Message;

use crate::error::ContractError;
use crate::execute::is_message_verified;

pub fn verification_statuses(deps: Deps, messages: Vec<Message>) -> StdResult<Vec<(String, bool)>> {
    messages
        .into_iter()
        .map(|message| {
            is_message_verified(deps, &message).map(|verified| (message.id.to_string(), verified))
        })
        .collect::<Result<Vec<(String, bool)>, ContractError>>()
        .map_err(Into::into)
}
