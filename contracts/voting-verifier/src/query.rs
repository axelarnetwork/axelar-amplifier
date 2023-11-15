use axelar_wasm_std::voting::{Poll, PollStatus};
use connection_router::state::{CrossChainId, Message};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult};

use crate::error::ContractError;
use crate::state::{self, POLLS, POLL_MESSAGES};

#[cw_serde]
pub enum VerificationStatus {
    Verified,
    NotVerified,
    InProgress, // still in an open poll
    None,       // not in a poll
}

pub fn is_verified(deps: Deps, messages: &[Message]) -> StdResult<Vec<(CrossChainId, bool)>> {
    messages
        .iter()
        .map(|message| {
            verification_status(deps, message).map(|status| match status {
                VerificationStatus::Verified => (message.cc_id.to_owned(), true),
                _ => (message.cc_id.to_owned(), false),
            })
        })
        .collect::<Result<Vec<(_, _)>, _>>()
        .map_err(Into::into)
}

pub fn verification_status(
    deps: Deps,
    message: &Message,
) -> Result<VerificationStatus, ContractError> {
    match POLL_MESSAGES.may_load(deps.storage, &message.cc_id)? {
        Some(stored) => {
            let poll = POLLS
                .load(deps.storage, stored.poll_id)
                .expect("invalid invariant: message poll not found");

            let verified = poll
                .consensus(stored.index_in_poll)
                .expect("invalid invariant: message not found in poll");

            if verified {
                if stored.msg != *message {
                    return Err(ContractError::MessageMismatch(message.cc_id.to_string()));
                }
                Ok(VerificationStatus::Verified)
            } else if is_finished(&poll) {
                Ok(VerificationStatus::NotVerified)
            } else {
                Ok(VerificationStatus::InProgress)
            }
        }
        None => Ok(VerificationStatus::None),
    }
}

fn is_finished(poll: &Poll) -> bool {
    match poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
            poll.status == PollStatus::Finished
        }
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{
        nonempty,
        voting::{PollID, WeightedPoll},
        Participant, Snapshot, Threshold,
    };
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint256, Uint64};

    use crate::state::PollMessage;

    use super::*;

    #[test]
    fn verification_status_message_mismatch() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let poll = poll();
        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &state::Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = message(1);
        POLL_MESSAGES
            .save(
                deps.as_mut().storage,
                &msg.cc_id,
                &PollMessage::new(message(2), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            verification_status(deps.as_ref(), &msg).unwrap_err(),
            ContractError::MessageMismatch(msg.cc_id.to_string())
        );
    }

    #[test]
    fn verification_status_in_progress() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let poll = poll();
        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &state::Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = message(1);
        POLL_MESSAGES
            .save(
                deps.as_mut().storage,
                &msg.cc_id,
                &PollMessage::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            verification_status(deps.as_ref(), &msg).unwrap(),
            VerificationStatus::InProgress
        );
        assert_eq!(
            vec![(msg.cc_id.clone(), false)],
            is_verified(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_verified() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let mut poll = poll();
        poll.tallies[idx] = Uint256::from(5u64);

        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &state::Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = message(1);
        POLL_MESSAGES
            .save(
                deps.as_mut().storage,
                &msg.cc_id,
                &PollMessage::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            verification_status(deps.as_ref(), &msg).unwrap(),
            VerificationStatus::Verified
        );
        assert_eq!(
            vec![(msg.cc_id.clone(), true)],
            is_verified(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_not_verified() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let mut poll = poll();
        poll.status = PollStatus::Finished;

        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &state::Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = message(1);
        POLL_MESSAGES
            .save(
                deps.as_mut().storage,
                &msg.cc_id,
                &PollMessage::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            verification_status(deps.as_ref(), &msg).unwrap(),
            VerificationStatus::NotVerified
        );
        assert_eq!(
            vec![(msg.cc_id.clone(), false)],
            is_verified(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_none() {
        let deps = mock_dependencies();
        let msg = message(1);

        assert_eq!(
            verification_status(deps.as_ref(), &msg).unwrap(),
            VerificationStatus::None
        );
        assert_eq!(
            vec![(msg.cc_id.clone(), false)],
            is_verified(deps.as_ref(), &[msg]).unwrap()
        );
    }

    fn message(id: u64) -> Message {
        Message {
            cc_id: CrossChainId {
                chain: "source_chain".parse().unwrap(),
                id: format!("id:{id}").parse().unwrap(),
            },
            source_address: format!("source_address{id}").parse().unwrap(),
            destination_chain: format!("destination_chain{id}").parse().unwrap(),
            destination_address: format!("destination_address{id}").parse().unwrap(),
            payload_hash: [0; 32],
        }
    }

    pub fn poll() -> WeightedPoll {
        let participants: nonempty::Vec<Participant> = vec!["addr1", "addr2", "addr3"]
            .into_iter()
            .map(|participant| Participant {
                address: Addr::unchecked(participant),
                weight: nonempty::Uint256::try_from(Uint256::one()).unwrap(),
            })
            .collect::<Vec<Participant>>()
            .try_into()
            .unwrap();

        let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
        let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
        let threshold: Threshold = (numerator, denominator).try_into().unwrap();

        let snapshot = Snapshot::new(threshold, participants);

        WeightedPoll::new(PollID::from(Uint64::one()), snapshot, 0, 5)
    }
}
