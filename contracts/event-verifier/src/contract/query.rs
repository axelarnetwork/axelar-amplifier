use axelar_wasm_std::voting::{PollId, PollStatus, Vote};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use cosmwasm_std::Deps;
use error_stack::{Result, ResultExt};
use crate::hash::hash_event_to_verify;

use crate::error::ContractError;
use crate::msg::{EventStatus, EventToVerify, PollData, PollResponse};
use crate::state::{poll_events, EventInPoll, CONFIG, POLLS};
use axelar_wasm_std::voting::WeightedPoll;

pub fn voting_threshold(deps: Deps) -> Result<MajorityThreshold, ContractError> {
    Ok(CONFIG
        .load(deps.storage)
        .change_context(ContractError::StorageError)?
        .voting_threshold)
}

pub fn current_fee(deps: Deps) -> Result<cosmwasm_std::Coin, ContractError> {
    Ok(CONFIG
        .load(deps.storage)
        .change_context(ContractError::StorageError)?
        .fee)
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
                .map(|status| EventStatus {
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

    Ok(PollResponse {
        poll,
        data,
        status,
    })
}

fn verification_status(
    deps: Deps,
    stored_poll_content: Option<EventInPoll>,
    content: &EventToVerify,
    cur_block_height: u64,
) -> VerificationStatus {
    match stored_poll_content {
        Some(stored) => {
            assert_eq!(stored.event, *content, "invalid invariant: content mismatch with the stored one");

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
    use super::*;
    use crate::state::{Config, CONFIG, POLLS};
    use axelar_wasm_std::{nonempty, MajorityThreshold, Threshold};
    use axelar_wasm_std::snapshot::{Participant, Snapshot};
    use axelar_wasm_std::voting::{PollStatus, Tallies};
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::{coin, Uint128, HexBinary, Fraction};
    use event_verifier_api::{EventData, EvmEvent, Event};
    use router_api::ChainName;

    fn make_config(api: &MockApi, fee_amount: u128, threshold: MajorityThreshold) -> Config {
        Config {
            service_registry_contract: api.addr_make("svc"),
            service_name: "service".parse().unwrap(),
            admin: api.addr_make("admin"),
            voting_threshold: threshold,
            block_expiry: 100u64.try_into().unwrap(),
            fee: coin(fee_amount, "uaxl"),
        }
    }

    fn snapshot_3_participants(api: &MockApi, threshold: MajorityThreshold) -> Snapshot {
        let participants = vec![
            Participant { address: api.addr_make("addr0"), weight: nonempty::Uint128::one() },
            Participant { address: api.addr_make("addr1"), weight: nonempty::Uint128::one() },
            Participant { address: api.addr_make("addr2"), weight: nonempty::Uint128::one() },
        ];
        let participants = nonempty::Vec::try_from(participants).unwrap();
        Snapshot::new(threshold, participants)
    }

    fn evm_event_json_with_index(index: u64) -> String {
        let tx_hash = axelar_wasm_std::fixed_size::HexBinary::<32>::try_from(vec![0u8; 32]).unwrap();
        let addr = axelar_wasm_std::fixed_size::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let ev = Event { contract_address: addr, event_index: index, topics: vec![], data: HexBinary::from(Vec::<u8>::new()) };
        let evm = EvmEvent { transaction_hash: tx_hash, transaction_details: None, events: vec![ev] };
        serde_json::to_string(&EventData::Evm(evm)).unwrap()
    }

    fn event(chain: &str, index: u64) -> EventToVerify {
        EventToVerify { source_chain: chain.parse().unwrap(), event_data: evm_event_json_with_index(index) }
    }

    fn threshold_two_of_three() -> MajorityThreshold {
        Threshold::try_from((2u64, 3u64)).unwrap().try_into().unwrap()
    }

    #[test]
    fn voting_threshold_returns_config_value() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let threshold = Threshold::try_from((3u64, 3u64)).unwrap().try_into().unwrap();
        CONFIG.save(deps.as_mut().storage, &make_config(&api, 5, threshold)).unwrap();

        let got = voting_threshold(deps.as_ref()).unwrap();
        assert_eq!(got.numerator().u64(), 3);
        assert_eq!(got.denominator().u64(), 3);
    }

    #[test]
    fn current_fee_returns_config_value() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG.save(deps.as_mut().storage, &make_config(&api, 42, threshold_two_of_three())).unwrap();

        let got = current_fee(deps.as_ref()).unwrap();
        assert_eq!(got, coin(42, "uaxl"));
    }

    #[test]
    fn poll_response_returns_poll_and_events() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG.save(deps.as_mut().storage, &make_config(&api, 0, threshold_two_of_three())).unwrap();

        let poll_id = 1u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let poll = WeightedPoll::new(poll_id, snapshot, 100, 2);
        POLLS.save(deps.as_mut().storage, poll_id, &poll).unwrap();

        let ev1 = event("chain-a", 0);
        let ev2 = event("chain-a", 1);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev1), &EventInPoll::new(ev1.clone(), poll_id, 0))
            .unwrap();
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev2), &EventInPoll::new(ev2.clone(), poll_id, 1))
            .unwrap();

        let res = poll_response(deps.as_ref(), 0, poll_id).unwrap();
        assert_eq!(res.poll.poll_id, poll_id);
        assert!(matches!(res.status, PollStatus::InProgress));
        match res.data {
            PollData::Events(evts) => {
                assert_eq!(evts.len(), 2);
                assert_eq!(evts[0], ev1);
                assert_eq!(evts[1], ev2);
            }
        }
    }

    #[test]
    fn event_status_covers_unknown_inprogress_verified_failed() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG.save(deps.as_mut().storage, &make_config(&api, 0, threshold_two_of_three())).unwrap();

        // Unknown
        let ev_unknown = event("chain-a", 10);
        let status = event_status(deps.as_ref(), &ev_unknown, 0).unwrap();
        assert!(matches!(status, VerificationStatus::Unknown));

        // InProgress (no consensus, not expired)
        let poll_id = 1u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let poll = WeightedPoll::new(poll_id, snapshot, 100, 1);
        POLLS.save(deps.as_mut().storage, poll_id, &poll).unwrap();
        let ev_inprogress = event("chain-a", 11);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev_inprogress), &EventInPoll::new(ev_inprogress.clone(), poll_id, 0))
            .unwrap();
        let status = event_status(deps.as_ref(), &ev_inprogress, 0).unwrap();
        assert!(matches!(status, VerificationStatus::InProgress));

        // SucceededOnSourceChain consensus
        let poll_id2 = 2u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let mut poll2 = WeightedPoll::new(poll_id2, snapshot, 100, 1);
        let mut tallies = Tallies::default();
        let quorum: Uint128 = poll2.quorum.into();
        tallies.tally(&Vote::SucceededOnChain, &quorum);
        poll2.tallies[0] = tallies;
        POLLS.save(deps.as_mut().storage, poll_id2, &poll2).unwrap();
        let ev_succeeded = event("chain-a", 12);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev_succeeded), &EventInPoll::new(ev_succeeded.clone(), poll_id2, 0))
            .unwrap();
        let status = event_status(deps.as_ref(), &ev_succeeded, 0).unwrap();
        assert!(matches!(status, VerificationStatus::SucceededOnSourceChain));

        // FailedOnSourceChain consensus
        let poll_id3 = 3u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let mut poll3 = WeightedPoll::new(poll_id3, snapshot, 100, 1);
        let mut tallies = Tallies::default();
        let quorum: Uint128 = poll3.quorum.into();
        tallies.tally(&Vote::FailedOnChain, &quorum);
        poll3.tallies[0] = tallies;
        POLLS.save(deps.as_mut().storage, poll_id3, &poll3).unwrap();
        let ev_failed = event("chain-a", 13);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev_failed), &EventInPoll::new(ev_failed.clone(), poll_id3, 0))
            .unwrap();
        let status = event_status(deps.as_ref(), &ev_failed, 0).unwrap();
        assert!(matches!(status, VerificationStatus::FailedOnSourceChain));

        // NotFoundOnSourceChain consensus
        let poll_id4 = 4u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let mut poll4 = WeightedPoll::new(poll_id4, snapshot, 100, 1);
        let mut tallies = Tallies::default();
        let quorum: Uint128 = poll4.quorum.into();
        tallies.tally(&Vote::NotFound, &quorum);
        poll4.tallies[0] = tallies;
        POLLS.save(deps.as_mut().storage, poll_id4, &poll4).unwrap();
        let ev_notfound = event("chain-a", 14);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev_notfound), &EventInPoll::new(ev_notfound.clone(), poll_id4, 0))
            .unwrap();
        let status = event_status(deps.as_ref(), &ev_notfound, 0).unwrap();
        assert!(matches!(status, VerificationStatus::NotFoundOnSourceChain));

        // FailedToVerify when expired with no consensus
        let poll_id5 = 5u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let poll5 = WeightedPoll::new(poll_id5, snapshot, 10, 1);
        POLLS.save(deps.as_mut().storage, poll_id5, &poll5).unwrap();
        let ev_failed_to_verify = event("chain-a", 15);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&ev_failed_to_verify), &EventInPoll::new(ev_failed_to_verify.clone(), poll_id5, 0))
            .unwrap();
        let status = event_status(deps.as_ref(), &ev_failed_to_verify, 11).unwrap();
        assert!(matches!(status, VerificationStatus::FailedToVerify));
    }

    #[test]
    fn events_status_aggregates_multiple() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        CONFIG.save(deps.as_mut().storage, &make_config(&api, 0, threshold_two_of_three())).unwrap();

        // Prepare three events: unknown, inprogress, succeeded
        let e_unknown = event("chain-a", 20);

        // inprogress
        let poll_id = 6u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let poll = WeightedPoll::new(poll_id, snapshot, 100, 1);
        POLLS.save(deps.as_mut().storage, poll_id, &poll).unwrap();
        let e_inprogress = event("chain-a", 21);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&e_inprogress), &EventInPoll::new(e_inprogress.clone(), poll_id, 0))
            .unwrap();

        // succeeded
        let poll_id2 = 7u64.into();
        let snapshot = snapshot_3_participants(&api, threshold_two_of_three());
        let mut poll2 = WeightedPoll::new(poll_id2, snapshot, 100, 1);
        let mut tallies = Tallies::default();
        let quorum: Uint128 = poll2.quorum.into();
        tallies.tally(&Vote::SucceededOnChain, &quorum);
        poll2.tallies[0] = tallies;
        POLLS.save(deps.as_mut().storage, poll_id2, &poll2).unwrap();
        let e_succeeded = event("chain-a", 22);
        poll_events()
            .save(deps.as_mut().storage, &hash_event_to_verify(&e_succeeded), &EventInPoll::new(e_succeeded.clone(), poll_id2, 0))
            .unwrap();

        let res = events_status(deps.as_ref(), &[e_unknown.clone(), e_inprogress.clone(), e_succeeded.clone()], 0).unwrap();
        assert_eq!(res.len(), 3);
        assert!(matches!(res[0].status, VerificationStatus::Unknown));
        assert!(matches!(res[1].status, VerificationStatus::InProgress));
        assert!(matches!(res[2].status, VerificationStatus::SucceededOnSourceChain));
    }
}
