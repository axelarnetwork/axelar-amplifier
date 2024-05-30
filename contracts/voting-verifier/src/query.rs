use axelar_wasm_std::{
    voting::{PollStatus, Vote},
    MajorityThreshold, VerificationStatus,
};
use cosmwasm_std::Deps;
use multisig::verifier_set::VerifierSet;
use router_api::Message;

use crate::{
    error::ContractError,
    state::{poll_messages, poll_verifier_sets, CONFIG},
};
use crate::{
    msg::MessageStatus,
    state::{self, Poll, PollContent, POLLS},
};

pub fn voting_threshold(deps: Deps) -> Result<MajorityThreshold, ContractError> {
    Ok(CONFIG.load(deps.storage)?.voting_threshold)
}

pub fn messages_status(
    deps: Deps,
    messages: &[Message],
) -> Result<Vec<MessageStatus>, ContractError> {
    messages
        .iter()
        .map(|message| {
            message_status(deps, message)
                .map(|status| MessageStatus::new(message.to_owned(), status))
        })
        .collect()
}

pub fn message_status(deps: Deps, message: &Message) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = poll_messages().may_load(deps.storage, &message.hash())?;

    Ok(verification_status(deps, loaded_poll_content, message))
}

pub fn verifier_set_status(
    deps: Deps,
    verifier_set: &VerifierSet,
) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = poll_verifier_sets().may_load(
        deps.storage,
        &verifier_set.hash().as_slice().try_into().unwrap(),
    )?;

    Ok(verification_status(deps, loaded_poll_content, verifier_set))
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
                Poll::Messages(poll) | Poll::ConfirmVerifierSet(poll) => poll
                    .consensus(stored.index_in_poll)
                    .expect("invalid invariant: message not found in poll"),
            };

            match consensus {
                Some(Vote::SucceededOnChain) => VerificationStatus::SucceededOnSourceChain,
                Some(Vote::FailedOnChain) => VerificationStatus::FailedOnSourceChain,
                Some(Vote::NotFound) => VerificationStatus::NotFoundOnSourceChain,
                None if is_finished(&poll) => VerificationStatus::FailedToVerify,
                None => VerificationStatus::InProgress,
            }
        }
        None => VerificationStatus::Unknown,
    }
}

fn is_finished(poll: &state::Poll) -> bool {
    match poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmVerifierSet(poll) => {
            poll.status == PollStatus::Finished
        }
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{
        msg_id::tx_hash_event_index::HexTxHashAndEventIndex,
        nonempty,
        voting::{PollId, Tallies, Vote, WeightedPoll},
        Participant, Snapshot, Threshold,
    };
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint128, Uint64};
    use router_api::CrossChainId;

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
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::InProgress
            )],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_verified() {
        let mut deps = mock_dependencies();
        let idx = 0;

        let mut poll = poll();
        poll.tallies[idx] = Tallies::default();
        poll.tallies[idx].tally(&Vote::SucceededOnChain, &Uint128::from(5u64));

        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &state::Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = message(1);
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::SucceededOnSourceChain
            )],
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
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<Message>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::FailedToVerify
            )],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    #[test]
    fn verification_status_not_verified() {
        let deps = mock_dependencies();
        let msg = message(1);

        assert_eq!(
            vec![MessageStatus::new(msg.clone(), VerificationStatus::Unknown)],
            messages_status(deps.as_ref(), &[msg]).unwrap()
        );
    }

    fn message(id: u64) -> Message {
        Message {
            cc_id: CrossChainId {
                chain: "source-chain".parse().unwrap(),
                id: HexTxHashAndEventIndex {
                    tx_hash: [0; 32],
                    event_index: id as u32,
                }
                .to_string()
                .try_into()
                .unwrap(),
            },
            source_address: format!("source_address{id}").parse().unwrap(),
            destination_chain: format!("destination-chain{id}").parse().unwrap(),
            destination_address: format!("destination_address{id}").parse().unwrap(),
            payload_hash: [0; 32],
        }
    }

    pub fn poll() -> WeightedPoll {
        let participants: nonempty::Vec<Participant> = vec!["addr1", "addr2", "addr3"]
            .into_iter()
            .map(|participant| Participant {
                address: Addr::unchecked(participant),
                weight: nonempty::Uint128::try_from(Uint128::one()).unwrap(),
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
