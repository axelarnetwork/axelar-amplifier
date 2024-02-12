use axelar_wasm_std::{
    operators::Operators,
    voting::{PollStatus, Vote},
    VerificationStatus,
};
use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::Deps;

use crate::error::ContractError;
use crate::state::{self, Poll, PollContent, POLLS, POLL_MESSAGES, POLL_WORKER_SETS};

pub fn messages_status(
    deps: Deps,
    messages: &[Message],
) -> Result<Vec<(CrossChainId, VerificationStatus)>, ContractError> {
    messages
        .iter()
        .map(|message| {
            message_status(deps, message).map(|status| (message.cc_id.to_owned(), status))
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn message_status(deps: Deps, message: &Message) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = POLL_MESSAGES.may_load(deps.storage, &message.hash())?;

    Ok(verification_status(deps, loaded_poll_content, message))
}

pub fn worker_set_status(
    deps: Deps,
    operators: &Operators,
) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = POLL_WORKER_SETS.may_load(deps.storage, &operators.hash())?;

    Ok(verification_status(deps, loaded_poll_content, operators))
}

fn verification_status<T: PartialEq + std::fmt::Debug>(
    deps: Deps,
    stored_poll_content: Option<PollContent<T>>,
    content: &T,
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
                Poll::Messages(poll) | Poll::ConfirmWorkerSet(poll) => poll
                    .consensus(stored.index_in_poll)
                    .expect("invalid invariant: message not found in poll"),
            };

            match consensus {
                Some(Vote::SucceededOnChain) => VerificationStatus::SucceededOnChain,
                Some(Vote::FailedOnChain) => VerificationStatus::FailedOnChain,
                Some(Vote::NotFound) => VerificationStatus::NotFound,
                None if is_finished(&poll) => VerificationStatus::FailedToVerify,
                None => VerificationStatus::InProgress,
            }
        }
        None => VerificationStatus::None,
    }
}

fn is_finished(poll: &state::Poll) -> bool {
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
        voting::{PollId, Tallies, Vote, WeightedPoll},
        Participant, Snapshot, Threshold,
    };
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint256, Uint64};

    use crate::state::PollContent;

    use super::*;

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
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![(msg.cc_id.clone(), VerificationStatus::InProgress)],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_verified() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let mut poll = poll();
        poll.tallies[idx] = Tallies::default();
        poll.tallies[idx].tally(&Vote::SucceededOnChain, &Uint256::from(5u64));

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
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![(msg.cc_id.clone(), VerificationStatus::SucceededOnChain)],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_failed_to_verify() {
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
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![(msg.cc_id.clone(), VerificationStatus::FailedToVerify)],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_not_verified() {
        let deps = mock_dependencies();
        let msg = message(1);

        assert_eq!(
            vec![(msg.cc_id.clone(), VerificationStatus::None)],
            messages_status(deps.as_ref(), &[msg]).unwrap()
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

        let snapshot = Snapshot::new(threshold.try_into().unwrap(), participants);

        WeightedPoll::new(PollId::from(Uint64::one()), snapshot, 0, 5)
    }
}
