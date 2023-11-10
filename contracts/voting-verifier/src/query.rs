use axelar_wasm_std::voting::{Poll, PollStatus};
use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::{Deps, StdResult};

use crate::error::ContractError;
use crate::state::{self, POLLS, POLL_MESSAGES};

enum MessageStatus {
    Verified,
    NotVerified,
    Pending, // still in an open poll
    None,
}

pub fn verification_statuses(
    deps: Deps,
    messages: Vec<Message>,
) -> StdResult<Vec<(CrossChainId, bool)>> {
    messages
        .into_iter()
        .map(|message| {
            message_status(deps, &message).map(|status| match status {
                MessageStatus::Verified => (message.cc_id, true),
                _ => (message.cc_id, false),
            })
        })
        .collect::<Result<Vec<(_, _)>, _>>()
        .map_err(Into::into)
}

pub fn message_status(deps: Deps, message: &Message) -> Result<MessageStatus, ContractError> {
    match POLL_MESSAGES.may_load(deps.storage, &message.cc_id)? {
        Some(stored) if stored.msg != *message => {
            Err(ContractError::MessageMismatch(message.cc_id.to_string()))
        }
        Some(stored) => {
            let poll = POLLS
                .load(deps.storage, stored.poll_id)
                .expect("invalid invariant: message poll not found");

            match poll {
                state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
                    if poll.status == PollStatus::InProgress {
                        return Ok(MessageStatus::Pending);
                    }
                }
            }

            let consensus = poll
                .consensus(stored.index_in_poll)
                .expect("invalid invariant: message not found in poll");

            match consensus {
                true => Ok(MessageStatus::Verified),
                false => Ok(MessageStatus::NotVerified),
            }
        }
        None => Ok(MessageStatus::None),
    }
}
