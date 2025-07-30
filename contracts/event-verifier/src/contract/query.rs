use axelar_wasm_std::voting::{PollId, PollStatus, Vote};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use cosmwasm_std::Deps;
use error_stack::{Result, ResultExt};

use crate::error::ContractError;
use crate::msg::{EventStatus, EventToVerify, PollData, PollResponse};
use crate::state::{poll_events, Poll, PollContent, CONFIG, POLLS};

pub fn voting_threshold(deps: Deps) -> Result<MajorityThreshold, ContractError> {
    Ok(CONFIG
        .load(deps.storage)
        .change_context(ContractError::StorageError)?
        .voting_threshold)
}

pub fn events_status(
    deps: Deps,
    events: &[EventToVerify],
    cur_block_height: u64,
) -> Result<Vec<EventStatus>, ContractError> {
    events
        .iter()
        .map(|event| {
            event_status(deps, event, cur_block_height)
                .map(|status| EventStatus::new(event.to_owned(), status))
        })
        .collect()
}

pub fn event_status(
    deps: Deps,
    event: &EventToVerify,
    cur_block_height: u64,
) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = poll_events()
        .may_load(deps.storage, &event.hash())
        .change_context(ContractError::StorageError)?;

    Ok(verification_status(
        deps,
        loaded_poll_content,
        event,
        cur_block_height,
    ))
}

pub fn poll_response(
    deps: Deps,
    current_block_height: u64,
    poll_id: PollId,
) -> Result<PollResponse, ContractError> {
    let poll = POLLS
        .load(deps.storage, poll_id)
        .change_context(ContractError::PollNotFound)?;
    let (data, status) = match &poll {
        Poll::Events(poll) => {
            let events = poll_events()
                .idx
                .load_events(deps.storage, poll_id)
                .change_context(ContractError::StorageError)?;
            assert_eq!(
                poll.tallies.len(),
                events.len(),
                "data inconsistency for number of events in poll {}",
                poll.poll_id
            );

            (PollData::Events(events), poll.status(current_block_height))
        }
    };

    Ok(PollResponse {
        poll: poll.weighted_poll(),
        data,
        status,
    })
}

fn verification_status<T: PartialEq + std::fmt::Debug>(
    deps: Deps,
    stored_poll_content: Option<PollContent<T>>,
    content: &T,
    cur_block_height: u64,
) -> VerificationStatus {
    match stored_poll_content {
        Some(stored) => {
            assert_eq!(
                stored.content, *content,
                "invalid invariant: content mismatch with the stored one"
            );

            let poll = POLLS
                .load(deps.storage, stored.poll_id)
                .expect("invalid invariant: content's poll not found");

            let consensus = match &poll {
                Poll::Events(poll) => poll
                    .consensus(stored.index_in_poll)
                    .expect("invalid invariant: event not found in poll"),
            };

            match consensus {
                Some(Vote::SucceededOnChain) => VerificationStatus::SucceededOnSourceChain,
                Some(Vote::FailedOnChain) => VerificationStatus::FailedOnSourceChain,
                Some(Vote::NotFound) => VerificationStatus::NotFoundOnSourceChain,
                None if voting_completed(&poll, cur_block_height) => {
                    VerificationStatus::FailedToVerify
                }
                None => VerificationStatus::InProgress,
            }
        }
        None => VerificationStatus::Unknown,
    }
}

fn voting_completed(poll: &Poll, cur_block_height: u64) -> bool {
    match poll {
        Poll::Events(poll) => {
            matches!(
                poll.status(cur_block_height),
                PollStatus::Expired | PollStatus::Finished
            )
        }
    }
}

#[cfg(test)]
mod tests {
    // All tests removed as they depend on message functionality that has been removed
}
