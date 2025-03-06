use axelar_wasm_std::voting::{PollId, PollStatus, Vote};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use cosmwasm_std::{Deps, Storage};
use xrpl_types::msg::XRPLMessage;

use crate::error::ContractError;
use crate::msg::{MessageStatus, PollData, PollResponse};
use crate::state::{poll_messages, Poll, PollContent, CONFIG, POLLS};

pub fn voting_threshold(deps: Deps) -> Result<MajorityThreshold, ContractError> {
    Ok(CONFIG.load(deps.storage)?.voting_threshold)
}

pub fn messages_status(
    storage: &dyn Storage,
    messages: &[XRPLMessage],
    cur_block_height: u64,
) -> Result<Vec<MessageStatus>, ContractError> {
    messages
        .iter()
        .map(|message| {
            message_status(storage, message, cur_block_height)
                .map(|status| MessageStatus::new(message.to_owned(), status))
        })
        .collect()
}

pub fn message_status(
    storage: &dyn Storage,
    message: &XRPLMessage,
    cur_block_height: u64,
) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = poll_messages().may_load(storage, &message.hash())?;

    Ok(verification_status(
        storage,
        loaded_poll_content,
        message,
        cur_block_height,
    ))
}

pub fn poll_response(
    deps: Deps,
    current_block_height: u64,
    poll_id: PollId,
) -> Result<PollResponse, ContractError> {
    let poll = POLLS.load(deps.storage, poll_id)?;
    let (data, status) = match &poll {
        Poll::Messages(poll) => {
            let msgs = poll_messages().idx.load_messages(deps.storage, poll_id)?;
            assert_eq!(
                poll.tallies.len(),
                msgs.len(),
                "data inconsistency for number of messages in poll {}",
                poll.poll_id
            );

            (PollData::Messages(msgs), poll.status(current_block_height))
        }
    };

    Ok(PollResponse {
        poll: poll.weighted_poll(),
        data,
        status,
    })
}

fn verification_status<T: PartialEq + std::fmt::Debug>(
    storage: &dyn Storage,
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
                .load(storage, stored.poll_id)
                .expect("invalid invariant: content's poll not found");

            let consensus = match &poll {
                Poll::Messages(poll) => poll
                    .consensus(stored.index_in_poll)
                    .expect("invalid invariant: message not found in poll"),
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
        Poll::Messages(poll) => {
            matches!(
                poll.status(cur_block_height),
                PollStatus::Expired | PollStatus::Finished
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::voting::{PollId, Tallies, Vote, WeightedPoll};
    use axelar_wasm_std::{nonempty, Participant, Snapshot, Threshold};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
    use itertools::Itertools;
    use xrpl_types::msg::XRPLUserMessage;
    use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount};

    use super::*;
    use crate::state::PollContent;

    #[test]
    fn verification_status_in_progress() {
        let mut deps = mock_dependencies();
        let idx = 0;
        let cur_block_height = 100;

        let poll = poll(cur_block_height + 10);
        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = user_message(1);
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<XRPLMessage>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::InProgress
            )],
            messages_status(&deps.storage, &[msg], cur_block_height).unwrap()
        );
    }

    #[test]
    fn verification_status_verified() {
        let mut deps = mock_dependencies();
        let idx = 0;
        let cur_block_height = 100;

        let mut poll = poll(cur_block_height + 10);
        poll.tallies[idx] = Tallies::default();
        poll.tallies[idx].tally(&Vote::SucceededOnChain, &Uint128::from(5u64));

        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = user_message(1);
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<XRPLMessage>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::SucceededOnSourceChain
            )],
            messages_status(&deps.storage, &[msg], cur_block_height).unwrap()
        );
    }

    #[test]
    fn verification_status_failed_to_verify() {
        let mut deps = mock_dependencies();
        let idx = 0;
        let cur_block_height = 100;
        let poll_duration = 10;
        let expires_at = cur_block_height + poll_duration;

        let poll = poll(expires_at);

        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &Poll::Messages(poll.clone()),
            )
            .unwrap();

        let msg = user_message(1);
        poll_messages()
            .save(
                deps.as_mut().storage,
                &msg.hash(),
                &PollContent::<XRPLMessage>::new(msg.clone(), poll.poll_id, idx),
            )
            .unwrap();

        assert_eq!(
            vec![MessageStatus::new(
                msg.clone(),
                VerificationStatus::FailedToVerify
            )],
            messages_status(&deps.storage, &[msg], expires_at).unwrap()
        );
    }

    #[test]
    fn verification_status_not_verified() {
        let deps = mock_dependencies();
        let msg = user_message(1);

        assert_eq!(
            vec![MessageStatus::new(msg.clone(), VerificationStatus::Unknown)],
            messages_status(&deps.storage, &[msg], 0).unwrap()
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn poll_response() {
        let mut deps = mock_dependencies();

        let poll = poll(1);
        POLLS
            .save(
                deps.as_mut().storage,
                poll.poll_id,
                &Poll::Messages(poll.clone()),
            )
            .unwrap();

        let messages = (0..poll.poll_size as u32).map(user_message);
        messages.clone().enumerate().for_each(|(idx, msg)| {
            poll_messages()
                .save(
                    deps.as_mut().storage,
                    &msg.hash(),
                    &PollContent::<XRPLMessage>::new(msg, poll.poll_id, idx),
                )
                .unwrap()
        });

        assert_eq!(
            PollResponse {
                poll: poll.clone(),
                data: PollData::Messages(messages.collect_vec()),
                status: PollStatus::Expired
            },
            super::poll_response(deps.as_ref(), mock_env().block.height, poll.poll_id).unwrap()
        );
    }

    fn user_message(id: u32) -> XRPLMessage {
        XRPLMessage::UserMessage(XRPLUserMessage {
            tx_id: HexTxHash::new([0; 32]),
            source_address: XRPLAccountId::new([0; 20]),
            destination_chain: format!("destination-chain{id}").parse().unwrap(),
            destination_address: nonempty::String::try_from("1234").unwrap(),
            payload_hash: None,
            amount: XRPLPaymentAmount::Drops(100),
            gas_fee_amount: XRPLPaymentAmount::Drops(100),
        })
    }

    pub fn poll(expires_at: u64) -> WeightedPoll {
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

        WeightedPoll::new(PollId::from(Uint64::one()), snapshot, expires_at, 5)
    }
}
