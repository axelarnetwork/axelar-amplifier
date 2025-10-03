use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use cosmwasm_std::Deps;
use error_stack::{Result, ResultExt};
use event_verifier_api::{EventStatus, EventToVerify, PollData, PollResponse};

use crate::error::ContractError;
use crate::hash::hash_event_to_verify;
use crate::state::{poll_events, EventInPoll, CONFIG, POLLS};

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
            event_status(deps, event, cur_block_height).map(|status| EventStatus {
                event: event.to_owned(),
                status,
            })
        })
        .collect()
}

pub fn event_status(
    deps: Deps,
    event: &EventToVerify,
    cur_block_height: u64,
) -> Result<VerificationStatus, ContractError> {
    let loaded_poll_content = poll_events()
        .may_load(deps.storage, &hash_event_to_verify(event))
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

    let data = PollData::Events(events);
    let status = poll.status(current_block_height);

    Ok(PollResponse { poll, data, status })
}

fn verification_status(
    deps: Deps,
    stored_poll_content: Option<EventInPoll>,
    content: &EventToVerify,
    cur_block_height: u64,
) -> VerificationStatus {
    match stored_poll_content {
        Some(stored) => {
            assert_eq!(
                stored.event, *content,
                "invalid invariant: content mismatch with the stored one"
            );

            let poll = POLLS
                .load(deps.storage, stored.poll_id)
                .expect("invalid invariant: content's poll not found");

            let consensus = poll
                .consensus(stored.index_in_poll)
                .expect("invalid invariant: event not found in poll");

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

fn voting_completed(poll: &WeightedPoll, cur_block_height: u64) -> bool {
    matches!(
        poll.status(cur_block_height),
        PollStatus::Expired | PollStatus::Finished
    )
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::snapshot::{Participant, Snapshot};
    use axelar_wasm_std::voting::{PollStatus, Tallies, Vote};
    use axelar_wasm_std::{nonempty, MajorityThreshold, Threshold};
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::{Fraction, HexBinary, Storage, Uint128};
    use event_verifier_api::{Event, EventData, EvmEvent};

    use super::*;
    use crate::state::{Config, CONFIG, POLLS, POLL_ID};

    fn make_config(api: &MockApi, threshold: MajorityThreshold) -> Config {
        Config {
            service_registry_contract: api.addr_make("svc"),
            service_name: "service".parse().unwrap(),
            voting_threshold: threshold,
            block_expiry: 100u64.try_into().unwrap(),
        }
    }

    fn snapshot_3_participants(api: &MockApi, threshold: MajorityThreshold) -> Snapshot {
        let participants = vec![
            Participant {
                address: api.addr_make("addr0"),
                weight: nonempty::Uint128::one(),
            },
            Participant {
                address: api.addr_make("addr1"),
                weight: nonempty::Uint128::one(),
            },
            Participant {
                address: api.addr_make("addr2"),
                weight: nonempty::Uint128::one(),
            },
        ];
        let participants = nonempty::Vec::try_from(participants).unwrap();
        Snapshot::new(threshold, participants)
    }

    fn make_event_data(index: u64, seed: u64) -> String {
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&seed.to_be_bytes());
        let mut tx = [0u8; 32];
        tx[..8].copy_from_slice(&seed_bytes);
        let tx_hash = axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(tx.to_vec()).unwrap();
        let addr = axelar_wasm_std::fixed_size::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let event = Event {
            contract_address: addr,
            event_index: index,
            topics: vec![],
            data: HexBinary::from(Vec::<u8>::new()),
        };
        let evm = EvmEvent {
            transaction_hash: tx_hash,
            transaction_details: None,
            events: vec![event],
        };
        serde_json::to_string(&EventData::Evm(evm)).unwrap()
    }

    fn event(chain: &str, index: u64) -> EventToVerify {
        EventToVerify {
            source_chain: chain.parse().unwrap(),
            event_data: make_event_data(index, 0),
        }
    }

    fn event_with_seed(chain: &str, index: u64, seed: u64) -> EventToVerify {
        EventToVerify {
            source_chain: chain.parse().unwrap(),
            event_data: make_event_data(index, seed),
        }
    }

    fn threshold_two_of_three() -> MajorityThreshold {
        Threshold::try_from((2u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn store_poll_with_snapshot(
        storage: &mut dyn Storage,
        poll_id: PollId,
        snapshot: Snapshot,
        expiry: u64,
        poll_size: usize,
    ) -> WeightedPoll {
        let poll = WeightedPoll::new(poll_id, snapshot, expiry, poll_size);
        POLLS.save(storage, poll_id, &poll).unwrap();
        poll
    }

    fn store_poll(
        storage: &mut dyn Storage,
        api: &MockApi,
        poll_id: PollId,
        poll_size: usize,
        expiry: u64,
    ) -> WeightedPoll {
        let snapshot = snapshot_3_participants(api, threshold_two_of_three());
        store_poll_with_snapshot(storage, poll_id, snapshot, expiry, poll_size)
    }

    fn set_consensus_at_index(
        storage: &mut dyn Storage,
        poll_id: PollId,
        index: usize,
        vote: Vote,
    ) {
        let mut poll = POLLS.load(storage, poll_id).unwrap();
        let mut tallies = Tallies::default();
        let quorum: Uint128 = poll.quorum.into();
        tallies.tally(&vote, &quorum);
        poll.tallies[index] = tallies;
        POLLS.save(storage, poll_id, &poll).unwrap();
    }

    fn store_event_in_poll(
        storage: &mut dyn Storage,
        event: &EventToVerify,
        poll_id: PollId,
        idx: usize,
    ) {
        poll_events()
            .save(
                storage,
                &hash_event_to_verify(event),
                &EventInPoll::new(event.clone(), poll_id, idx),
            )
            .unwrap();
    }

    fn create_event_and_poll(
        storage: &mut dyn Storage,
        api: &MockApi,
        expiry: u64,
        num_events: usize,
    ) -> (Vec<EventToVerify>, PollId) {
        let poll_id = POLL_ID.incr(storage).unwrap();
        let _poll = store_poll(storage, api, poll_id, num_events, expiry);

        // use index within poll as event_index; derive unique tx hash from pid
        let poll_id_str: String = poll_id.into();
        let poll_id_num: u64 = poll_id_str.parse().unwrap();
        let events: Vec<EventToVerify> = (0..num_events)
            .map(|idx| event_with_seed("chain-a", idx as u64, poll_id_num))
            .collect();
        for (idx, event) in events.iter().enumerate() {
            store_event_in_poll(storage, event, poll_id, idx);
        }
        (events, poll_id)
    }

    #[test]
    fn voting_threshold_returns_config_value() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let threshold = Threshold::try_from((3u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        CONFIG
            .save(deps.as_mut().storage, &make_config(&api, threshold))
            .unwrap();

        let got = voting_threshold(deps.as_ref()).unwrap();
        assert_eq!(got.numerator().u64(), 3);
        assert_eq!(got.denominator().u64(), 3);
    }

    #[test]
    fn poll_response_returns_poll_and_events() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG
            .save(
                deps.as_mut().storage,
                &make_config(&api, threshold_two_of_three()),
            )
            .unwrap();

        let (events, poll_id) = create_event_and_poll(deps.as_mut().storage, &api, 100, 2);
        let event1 = events[0].clone();
        let event2 = events[1].clone();

        let res = poll_response(deps.as_ref(), 0, poll_id).unwrap();
        assert_eq!(res.poll.poll_id, poll_id);
        assert!(matches!(res.status, PollStatus::InProgress));
        match res.data {
            PollData::Events(evts) => {
                assert_eq!(evts.len(), 2);
                assert_eq!(evts[0], event1);
                assert_eq!(evts[1], event2);
            }
        }
    }

    #[test]
    fn event_status_covers_unknown_inprogress_verified_failed() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG
            .save(
                deps.as_mut().storage,
                &make_config(&api, threshold_two_of_three()),
            )
            .unwrap();

        // Unknown
        let event_unknown = event("chain-a", 10);
        let status = event_status(deps.as_ref(), &event_unknown, 0).unwrap();
        assert!(matches!(status, VerificationStatus::Unknown));

        // InProgress (no consensus, not expired)
        let (events, _poll_id) = create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        let status = event_status(deps.as_ref(), &events[0], 0).unwrap();
        assert!(matches!(status, VerificationStatus::InProgress));

        // SucceededOnSourceChain consensus
        let (events2, poll_id2) = create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        set_consensus_at_index(deps.as_mut().storage, poll_id2, 0, Vote::SucceededOnChain);
        let status = event_status(deps.as_ref(), &events2[0], 0).unwrap();
        assert!(matches!(status, VerificationStatus::SucceededOnSourceChain));

        // FailedOnSourceChain consensus
        let (events3, poll_id3) = create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        set_consensus_at_index(deps.as_mut().storage, poll_id3, 0, Vote::FailedOnChain);
        let status = event_status(deps.as_ref(), &events3[0], 0).unwrap();
        assert!(matches!(status, VerificationStatus::FailedOnSourceChain));

        // NotFoundOnSourceChain consensus
        let (events4, poll_id4) = create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        set_consensus_at_index(deps.as_mut().storage, poll_id4, 0, Vote::NotFound);
        let status = event_status(deps.as_ref(), &events4[0], 0).unwrap();
        assert!(matches!(status, VerificationStatus::NotFoundOnSourceChain));

        // FailedToVerify when expired with no consensus
        let (events5, _poll_id5) = create_event_and_poll(deps.as_mut().storage, &api, 10, 1);
        let status = event_status(deps.as_ref(), &events5[0], 11).unwrap();
        assert!(matches!(status, VerificationStatus::FailedToVerify));
    }

    #[test]
    fn events_status_aggregates_multiple() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG
            .save(
                deps.as_mut().storage,
                &make_config(&api, threshold_two_of_three()),
            )
            .unwrap();

        // Prepare three events: unknown, inprogress, succeeded
        let event_unknown = event("chain-a", 20);

        // inprogress
        let (event_inprogress_vec, _poll_id_inprogress) =
            create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        let event_inprogress = event_inprogress_vec[0].clone();

        // succeeded
        let (event_succeeded_vec, poll_id_succeeded) =
            create_event_and_poll(deps.as_mut().storage, &api, 100, 1);
        let event_succeeded = event_succeeded_vec[0].clone();
        set_consensus_at_index(
            deps.as_mut().storage,
            poll_id_succeeded,
            0,
            Vote::SucceededOnChain,
        );

        let res = events_status(
            deps.as_ref(),
            &[
                event_unknown.clone(),
                event_inprogress.clone(),
                event_succeeded.clone(),
            ],
            0,
        )
        .unwrap();
        assert_eq!(res.len(), 3);
        assert!(matches!(res[0].status, VerificationStatus::Unknown));
        assert!(matches!(res[1].status, VerificationStatus::InProgress));
        assert!(matches!(
            res[2].status,
            VerificationStatus::SucceededOnSourceChain
        ));
    }
}
