use crate::hash::hash_event_to_verify;
use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::voting::{PollId, PollResults, Vote, WeightedPoll};
use axelar_wasm_std::{snapshot, MajorityThreshold, VerificationStatus};
use cosmwasm_std::{
    Deps, DepsMut, Env, Event, MessageInfo, OverflowError, OverflowOperation, Response, Storage,
};
use error_stack::{report, Report, Result, ResultExt};
use router_api::ChainName;
use service_registry::WeightedVerifier;

use crate::contract::query::event_status;
use crate::error::ContractError;
use crate::events::{self, PollMetadata};
use crate::state::{self, CONFIG, POLLS, POLL_ID, VOTES};

pub fn update_voting_threshold(
    deps: DepsMut,
    new_voting_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    CONFIG
        .update(
            deps.storage,
            |mut config| -> Result<_, cosmwasm_std::StdError> {
                config.voting_threshold = new_voting_threshold;
                Ok(config)
            },
        )
        .change_context(ContractError::StorageError)?;
    Ok(Response::new())
}

pub fn verify_events(
    deps: DepsMut,
    env: Env,
    events: Vec<event_verifier_api::EventToVerify>,
) -> Result<Response, ContractError> {
    if events.is_empty() {
        return Err(report!(ContractError::EmptyEvents));
    }

    let config = CONFIG.load(deps.storage).expect("failed to load config");

    let events = events.try_map(|event| {
        event_status(deps.as_ref(), &event, env.block.height).map(|status| (status, event))
    })?;

    let events_to_verify: Vec<event_verifier_api::EventToVerify> = events
        .into_iter()
        .filter_map(|(status, event)| match status {
            VerificationStatus::NotFoundOnSourceChain
            | VerificationStatus::FailedToVerify
            | VerificationStatus::Unknown => Some(event),
            VerificationStatus::InProgress
            | VerificationStatus::SucceededOnSourceChain
            | VerificationStatus::FailedOnSourceChain => None,
        })
        .collect();

    if events_to_verify.is_empty() {
        return Ok(Response::new());
    }

    // Ensure all events to verify have the same source chain
    let source_chain = &events_to_verify[0].source_chain;
    let same_chain = events_to_verify
        .iter()
        .all(|e| &e.source_chain == source_chain);
    if !same_chain {
        return Err(report!(ContractError::SourceChainMismatch(
            source_chain.clone(),
        )));
    }

    // Check for duplicate events by comparing hashes
    let event_hashes: std::collections::HashSet<_> =
        events_to_verify.iter().map(hash_event_to_verify).collect();
    if event_hashes.len() != events_to_verify.len() {
        return Err(report!(ContractError::DuplicateEvents));
    }

    // Get source chain from the first event - all events in a batch should have the same source chain
    let snapshot = take_snapshot(deps.as_ref(), source_chain)?;
    let participants = snapshot.participants();
    let expires_at = calculate_expiration(env.block.height, config.block_expiry.into())?;

    let id = create_events_poll(deps.storage, expires_at, snapshot, events_to_verify.len())?;

    for (idx, event) in events_to_verify.iter().enumerate() {
        state::poll_events()
            .save(
                deps.storage,
                &hash_event_to_verify(event),
                &state::EventInPoll::new(event.clone(), id, idx),
            )
            .change_context(ContractError::StorageError)?;
    }

    Ok(Response::new().add_event(events::Event::EventsPollStarted {
        events: events_to_verify.clone(),
        metadata: PollMetadata {
            poll_id: id,
            source_chain: source_chain.clone(),
            expires_at,
            participants,
        },
    }))
}

fn poll_results(poll: &WeightedPoll) -> PollResults {
    poll.results()
}

fn make_quorum_event(
    vote: Option<Vote>,
    index_in_poll: u32,
    poll_id: &PollId,
    _poll: &WeightedPoll,
    deps: &DepsMut,
) -> Result<Option<Event>, ContractError> {
    let status = vote.map(|vote| match vote {
        Vote::SucceededOnChain => VerificationStatus::SucceededOnSourceChain,
        Vote::FailedOnChain => VerificationStatus::FailedOnSourceChain,
        Vote::NotFound => VerificationStatus::NotFoundOnSourceChain,
    });
    let event = state::poll_events()
        .idx
        .load_event(deps.storage, *poll_id, index_in_poll)
        .change_context(ContractError::StorageError)?
        .expect("event must exist in poll when vote is cast");

    Ok(status.map(|status| {
        events::Event::QuorumReached {
            content: event,
            status,
            poll_id: *poll_id,
        }
        .into()
    }))
}

pub fn vote(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: PollId,
    votes: Vec<Vote>,
) -> Result<Response, ContractError> {
    let poll = POLLS
        .may_load(deps.storage, poll_id)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::PollNotFound)?;

    let results_before_voting = poll_results(&poll);

    let poll = poll
        .cast_vote(env.block.height, &info.sender, votes.clone())
        .map_err(ContractError::from)?;
    POLLS
        .save(deps.storage, poll_id, &poll)
        .change_context(ContractError::StorageError)?;

    let results_after_voting = poll_results(&poll);

    let quorum_events = results_after_voting
        .difference(results_before_voting)
        .expect("failed to substract poll results")
        .0
        .into_iter()
        .enumerate()
        .map(|(index_in_poll, vote)| {
            let idx = u32::try_from(index_in_poll)
                .expect("the amount of votes should never overflow u32");
            make_quorum_event(vote, idx, &poll_id, &poll, &deps)
        })
        .collect::<Result<Vec<Option<Event>>, _>>()?;

    VOTES
        .save(deps.storage, (poll_id, info.sender.to_string()), &votes)
        .change_context(ContractError::StorageError)?;

    Ok(Response::new()
        .add_event(events::Event::Voted {
            poll_id,
            voter: info.sender,
            votes,
        })
        .add_events(quorum_events.into_iter().flatten()))
}

fn take_snapshot(deps: Deps, chain: &ChainName) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");

    let service_registry: service_registry_api::Client =
        client::ContractClient::new(deps.querier, &config.service_registry_contract).into();

    let verifiers: Vec<WeightedVerifier> = service_registry
        .active_verifiers(config.service_name.into(), chain.to_owned())
        .change_context(ContractError::FailedToBuildSnapshot)?;

    let participants = verifiers
        .into_iter()
        .map(WeightedVerifier::into)
        .collect::<Vec<snapshot::Participant>>();

    Ok(snapshot::Snapshot::new(
        config.voting_threshold,
        participants.try_into().map_err(ContractError::from)?,
    ))
}

fn create_events_poll(
    store: &mut dyn Storage,
    expires_at: u64,
    snapshot: snapshot::Snapshot,
    poll_size: usize,
) -> Result<PollId, ContractError> {
    let id = POLL_ID
        .incr(store)
        .change_context(ContractError::StorageError)?;

    let poll = WeightedPoll::new(id, snapshot, expires_at, poll_size);
    POLLS
        .save(store, id, &poll)
        .change_context(ContractError::StorageError)?;

    Ok(id)
}

fn calculate_expiration(block_height: u64, block_expiry: u64) -> Result<u64, ContractError> {
    block_height
        .checked_add(block_expiry)
        .ok_or_else(|| OverflowError::new(OverflowOperation::Add))
        .map_err(ContractError::from)
        .map_err(Report::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{execute, instantiate, query};
    use assert_ok::assert_ok;
    use axelar_wasm_std::fixed_size;
    use axelar_wasm_std::Threshold;
    use axelar_wasm_std::{nonempty, MajorityThreshold};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::to_json_binary;
    use cosmwasm_std::{coin, Empty, HexBinary, OwnedDeps, Uint128, WasmQuery};
    use event_verifier_api::{Event, EventData, EvmEvent};
    use event_verifier_api::{EventToVerify, InstantiateMsg};
    use service_registry::{AuthorizationState, BondingState, Verifier, WeightedVerifier};

    const SERVICE_REGISTRY_ADDRESS: &str = "service_registry_address";
    const SERVICE_NAME: &str = "service_name";
    const GOVERNANCE: &str = "governance";
    const POLL_BLOCK_EXPIRY: u64 = 100;

    fn initial_voting_threshold() -> MajorityThreshold {
        Threshold::try_from((51, 100)).unwrap().try_into().unwrap()
    }

    fn verifiers(num: usize) -> Vec<Verifier> {
        (0..num)
            .map(|i| Verifier {
                address: MockApi::default().addr_make(format!("addr{}", i).as_str()),
                bonding_state: BondingState::Bonded {
                    amount: Uint128::from(100u128).try_into().unwrap(),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
            .collect()
    }

    fn setup(verifiers: Vec<Verifier>) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let service_registry = api.addr_make(SERVICE_REGISTRY_ADDRESS);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("admin"), &[]),
            InstantiateMsg {
                governance_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                service_registry_address: service_registry.as_str().parse().unwrap(),
                service_name: SERVICE_NAME.parse().unwrap(),
                admin_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                voting_threshold: initial_voting_threshold(),
                block_expiry: POLL_BLOCK_EXPIRY.try_into().unwrap(),
                fee: coin(0, "uaxl"),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == service_registry.as_str() =>
            {
                Ok(to_json_binary(
                    &verifiers
                        .clone()
                        .into_iter()
                        .map(|v| WeightedVerifier {
                            verifier_info: v,
                            weight: nonempty::Uint128::one(),
                        })
                        .collect::<Vec<WeightedVerifier>>(),
                )
                .into())
                .into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    #[test]
    fn verify_events_should_error_on_empty_input() {
        let mut deps = setup(verifiers(2));

        // empty events should error
        let err = verify_events(deps.as_mut(), mock_env(), vec![]).unwrap_err();
        assert_eq!(err.to_string(), ContractError::EmptyEvents.to_string());
    }

    #[test]
    fn verify_events_with_mixed_source_chains_should_error() {
        let mut deps = setup(verifiers(2));

        // Create events with different source chains manually
        let event1 = EventToVerify {
            source_chain: "ethereum".parse().unwrap(),
            event_data: evm_event_json_from_seed("event1"),
        };
        let event2 = EventToVerify {
            source_chain: "polygon".parse().unwrap(),
            event_data: evm_event_json_from_seed("event2"),
        };

        let err = verify_events(deps.as_mut(), mock_env(), vec![event1, event2]).unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::SourceChainMismatch("ethereum".parse().unwrap()).to_string()
        );
    }

    #[test]
    fn verify_events_should_error_on_duplicate_events() {
        let mut deps = setup(verifiers(2));

        // Create duplicate events (same seed will produce same hash)
        let event1 = event("duplicate-test");
        let event2 = event("duplicate-test"); // Same seed, should be duplicate

        let err = verify_events(deps.as_mut(), mock_env(), vec![event1, event2]).unwrap_err();
        assert_eq!(err.to_string(), ContractError::DuplicateEvents.to_string());
    }

    #[test]
    fn cannot_reverify_in_progress() {
        let mut deps = setup(verifiers(3));
        let ev = event("test-event");

        // Unknown -> should be verified (creates poll)
        create_poll(&mut deps, &ev);

        // InProgress -> should NOT be re-verified
        let res = verify_events(deps.as_mut(), mock_env(), vec![ev.clone()]).unwrap();
        assert!(res.events.is_empty());
    }

    #[test]
    fn can_reverify_failed_to_verify() {
        let mut deps = setup(verifiers(3));
        let ev = event("test-event");

        // Create poll and let it expire to FailedToVerify
        create_poll(&mut deps, &ev);

        // Advance to expiry -> FailedToVerify -> should be re-verified
        let mut env = mock_env();
        env.block.height += 100; // equals block_expiry
        let res = verify_events(deps.as_mut(), env, vec![ev.clone()]).unwrap();
        // A new poll should be started
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));
    }

    #[test]
    fn can_reverify_not_found() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        // Create poll and vote NotFound to reach consensus (need 2 out of 3 for default threshold)
        create_poll_and_vote_to_consensus(&mut deps, &ev, &verifiers[0..2], Vote::NotFound);

        // NotFound -> should be re-verified
        let res = verify_events(deps.as_mut(), mock_env(), vec![ev.clone()]).unwrap();
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));
    }

    #[test]
    fn cannot_reverify_succeeded_on_chain() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        // Create poll and vote SucceededOnChain to reach consensus (need 2 out of 3 for default threshold)
        create_poll_and_vote_to_consensus(&mut deps, &ev, &verifiers[0..2], Vote::SucceededOnChain);

        // SucceededOnChain -> should NOT be re-verified
        let res = verify_events(deps.as_mut(), mock_env(), vec![ev.clone()]).unwrap();
        assert!(res.events.is_empty());
    }

    #[test]
    fn cannot_reverify_failed_on_chain() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        // Create poll and vote FailedOnChain to reach consensus (need 2 out of 3 for default threshold)
        create_poll_and_vote_to_consensus(&mut deps, &ev, &verifiers[0..2], Vote::FailedOnChain);

        // FailedOnSourceChain -> should NOT be re-verified
        let res = verify_events(deps.as_mut(), mock_env(), vec![ev.clone()]).unwrap();
        assert!(res.events.is_empty());
    }

    #[test]
    fn event_status_should_reflect_poll_state() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());

        let ev = event("test-event");
        // Initial status should be Unknown
        let res = query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
            .unwrap();
        assert_eq!(res[0].status, VerificationStatus::Unknown);

        // Status should be InProgress after poll creation
        create_poll(&mut deps, &ev);
        let res = query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
            .unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // Status should be FailedToVerify after poll expiration with no consensus
        let res = query::events_status(
            deps.as_ref(),
            &[ev.clone()],
            mock_env().block.height + POLL_BLOCK_EXPIRY,
        )
        .unwrap();
        assert_eq!(res[0].status, VerificationStatus::FailedToVerify);

        // now test specific vote combinations
        let test_cases = [
            (
                [
                    Vote::SucceededOnChain,
                    Vote::SucceededOnChain,
                    Vote::SucceededOnChain,
                ],
                VerificationStatus::SucceededOnSourceChain,
            ),
            (
                [
                    Vote::FailedOnChain,
                    Vote::FailedOnChain,
                    Vote::FailedOnChain,
                ],
                VerificationStatus::FailedOnSourceChain,
            ),
            (
                [Vote::NotFound, Vote::NotFound, Vote::NotFound],
                VerificationStatus::NotFoundOnSourceChain,
            ),
            (
                [
                    Vote::SucceededOnChain,
                    Vote::NotFound,
                    Vote::SucceededOnChain,
                ],
                VerificationStatus::SucceededOnSourceChain,
            ),
            (
                [Vote::SucceededOnChain, Vote::NotFound, Vote::NotFound],
                VerificationStatus::NotFoundOnSourceChain,
            ),
            (
                [Vote::SucceededOnChain, Vote::NotFound, Vote::FailedOnChain],
                VerificationStatus::InProgress,
            ),
        ];
        for (idx, (votes, expected_status)) in test_cases.iter().enumerate() {
            let ev = event(&format!("test-{}", idx));

            create_poll_and_cast_votes(&mut deps, &ev, &verifiers, votes.to_vec());

            let res =
                query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
                    .unwrap();
            assert_eq!(res[0].status, *expected_status);
        }
    }
    #[test]
    fn vote_should_error_when_poll_not_found() {
        let mut deps = setup(verifiers(1));
        let api = deps.api;

        let err = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("anyone"), &[]),
            99u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::PollNotFound.to_string());
    }

    #[test]
    fn vote_should_error_when_not_participant() {
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        // create a poll with single event
        let poll_id = create_poll(&mut deps, &ev);

        // cast vote from non-participant
        let non_participant = deps.api.addr_make("not-in-set");
        let err = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&non_participant, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::VoteError(axelar_wasm_std::voting::Error::NotParticipant).to_string()
        );
    }

    #[test]
    fn vote_should_error_when_already_voted() {
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        let poll_id = create_poll(&mut deps, &ev);

        // first vote ok
        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![Vote::FailedOnChain],
        ));

        // second vote by same participant should fail
        let err = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![Vote::FailedOnChain],
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::VoteError(axelar_wasm_std::voting::Error::AlreadyVoted).to_string()
        );
    }

    #[test]
    fn threshold_update_is_respected() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());

        // Update threshold from initial 2/3 to 3/3
        let three_of_three: MajorityThreshold = axelar_wasm_std::Threshold::try_from((3u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        assert_ok!(update_voting_threshold(deps.as_mut(), three_of_three));

        // Create a poll with one event
        let ev = event("test-event");
        let poll_id = create_poll(&mut deps, &ev);

        // Two votes should NOT reach quorum under 3/3
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        ));
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[1].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        ));
        let res = query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
            .unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // Third vote should reach quorum under 3/3 and succeed
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[2].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        ));
        let res = query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
            .unwrap();
        assert_eq!(res[0].status, VerificationStatus::SucceededOnSourceChain);
    }

    #[test]
    fn threshold_update_only_applies_to_new_polls() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());

        // Create poll under initial 2/3 threshold
        let ev = event("test-event");
        let poll_id = create_poll(&mut deps, &ev);

        // Update threshold to 3/3 for NEW polls
        let three_of_three: MajorityThreshold = axelar_wasm_std::Threshold::try_from((3u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        assert_ok!(update_voting_threshold(deps.as_mut(), three_of_three));

        // For existing poll, 2 votes should still reach quorum (old 2/3 threshold)
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        ));
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[1].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        ));

        let res = query::events_status(deps.as_ref(), &[ev.clone()], mock_env().block.height)
            .unwrap();
        assert_eq!(res[0].status, VerificationStatus::SucceededOnSourceChain);
    }

    #[test]
    fn poll_started_event_emitted_correctly() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());

        // Create events to verify using the existing helper function
        let event1 = event("poll-test-1");
        let event2 = event("poll-test-2");

        let events_to_verify = vec![event1.clone(), event2.clone()];

        // Call verify_events to trigger poll_started event
        let res = verify_events(deps.as_mut(), mock_env(), events_to_verify.clone()).unwrap();

        // Find the poll_started event
        let poll_started_events: Vec<_> = res
            .events
            .iter()
            .filter(|e| e.ty == "events_poll_started")
            .collect();
        assert_eq!(
            poll_started_events.len(),
            1,
            "Should emit exactly one poll_started event"
        );

        let poll_started_event = poll_started_events[0];

        // Verify events attribute - should contain the exact events we passed in
        let events_attr = poll_started_event
            .attributes
            .iter()
            .find(|attr| attr.key == "events")
            .unwrap();
        let deserialized_events: Vec<event_verifier_api::EventToVerify> =
            serde_json::from_str(&events_attr.value).unwrap();
        assert_eq!(
            deserialized_events, events_to_verify,
            "Events in poll_started event should match input events exactly"
        );

        // Verify metadata attribute
        let metadata_attr = poll_started_event
            .attributes
            .iter()
            .find(|attr| attr.key == "metadata")
            .unwrap();
        let metadata: crate::events::PollMetadata =
            serde_json::from_str(&metadata_attr.value).unwrap();

        // Verify poll_id is correct (should be 1 for the first poll)
        assert_eq!(
            metadata.poll_id,
            1u64.into(),
            "Poll ID should be 1 for first poll"
        );

        // Verify source_chain matches the events
        let expected_chain: router_api::ChainName = event1.source_chain;
        assert_eq!(
            metadata.source_chain, expected_chain,
            "Source chain should match event source chain"
        );

        // Verify expires_at is set correctly (current block height + POLL_BLOCK_EXPIRY)
        let expected_expiry = mock_env().block.height + POLL_BLOCK_EXPIRY;
        assert_eq!(
            metadata.expires_at, expected_expiry,
            "Expiry should be current block height + poll block expiry"
        );

        // Verify participants match the verifier set (order may differ, so sort both)
        let mut expected_participants: Vec<_> =
            verifiers.iter().map(|v| v.address.clone()).collect();
        expected_participants.sort();
        let mut actual_participants = metadata.participants.clone();
        actual_participants.sort();
        assert_eq!(
            actual_participants, expected_participants,
            "Participants should match the verifier addresses"
        );
    }

    #[test]
    fn events_in_same_poll_achieve_consensus_independently() {
        let verifiers = verifiers(3);
        let mut deps = setup(verifiers.clone());

        // Create three different events for the same poll using different seeds
        let event1 = event("ev1");
        let event2 = event("ev2");
        let event3 = event("ev3");
        let events = vec![event1.clone(), event2.clone(), event3.clone()];

        verify_events(deps.as_mut(), mock_env(), events.clone()).unwrap();

        let poll_id = state::POLL_ID.cur(deps.as_ref().storage);

        // Verifier 0: [Succeeded, NotFound, Succeeded]
        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![
                Vote::SucceededOnChain,
                Vote::NotFound,
                Vote::SucceededOnChain
            ],
        ));

        let res1 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[1].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain, Vote::NotFound, Vote::NotFound],
        )
        .unwrap();

        // event 1 and 2 should have reached quorum, event 3 should not
        let quorum_events: Vec<_> = res1
            .events
            .iter()
            .filter(|e| e.ty == "quorum_reached")
            .collect();
        assert_eq!(
            quorum_events.len(),
            2,
            "Should emit exactly two quorum_reached events after second vote"
        );

        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[2].address, &[]),
            poll_id,
            vec![Vote::NotFound, Vote::SucceededOnChain, Vote::FailedOnChain],
        ));

        let status_res =
            query::events_status(deps.as_ref(), &events, mock_env().block.height).unwrap();
        assert_eq!(
            status_res[0].status,
            VerificationStatus::SucceededOnSourceChain
        );
        assert_eq!(
            status_res[1].status,
            VerificationStatus::NotFoundOnSourceChain
        );
        assert_eq!(status_res[2].status, VerificationStatus::InProgress);
    }

    #[test]
    fn quorum_reached_event_emitted_exactly_on_quorum() {
        let verifiers = verifiers(5);
        let mut deps = setup(verifiers.clone());
        let ev = event("test-event");

        // Create poll with one event
        let poll_id = create_poll(&mut deps, &ev);

        // First vote (SucceededOnChain): no quorum yet, no quorum_reached event
        let res1 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(!res1.events.iter().any(|e| e.ty == "quorum_reached"));

        // Second vote (NotFound): still no quorum, no quorum_reached event
        let res2 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[1].address, &[]),
            poll_id,
            vec![Vote::NotFound],
        )
        .unwrap();
        assert!(!res2.events.iter().any(|e| e.ty == "quorum_reached"));

        // Third vote (SucceededOnChain): still no quorum (only 2 out of 5 SucceededOnChain = 40% < 51%), no quorum_reached event
        let res3 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[2].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(!res3.events.iter().any(|e| e.ty == "quorum_reached"));

        // Fourth vote (SucceededOnChain): reaches quorum (3 out of 5 SucceededOnChain = 60% > 51%), quorum_reached event emitted
        let res4 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[3].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        )
        .unwrap();

        // Verify exactly one quorum_reached event was emitted
        let quorum_events: Vec<_> = res4
            .events
            .iter()
            .filter(|e| e.ty == "quorum_reached")
            .collect();
        assert_eq!(quorum_events.len(), 1);

        // Verify the event contains the correct content
        let quorum_event = quorum_events[0];
        assert_eq!(quorum_event.attributes.len(), 3); // content, status, poll_id

        // Verify poll_id attribute
        let poll_id_attr = quorum_event
            .attributes
            .iter()
            .find(|attr| attr.key == "poll_id")
            .unwrap();
        assert_eq!(poll_id_attr.value, format!("\"{}\"", poll_id));

        // Verify status attribute
        let status_attr = quorum_event
            .attributes
            .iter()
            .find(|attr| attr.key == "status")
            .unwrap();
        assert_eq!(status_attr.value, "\"succeeded_on_source_chain\"");

        // Verify content attribute contains the full serialized event data
        let content_attr = quorum_event
            .attributes
            .iter()
            .find(|attr| attr.key == "content")
            .unwrap();

        // Deserialize the content attribute and compare directly to the original event
        let deserialized_event: event_verifier_api::EventToVerify =
            serde_json::from_str(&content_attr.value).unwrap();
        assert_eq!(deserialized_event, ev);

        // Fifth vote (SucceededOnChain): already at quorum; no new quorum_reached events
        let res5 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[4].address, &[]),
            poll_id,
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(!res5.events.iter().any(|e| e.ty == "quorum_reached"));
    }

    // Helper functions

    fn event(seed: &str) -> EventToVerify {
        EventToVerify {
            source_chain: "ethereum".parse().unwrap(),
            event_data: evm_event_json_from_seed(seed),
        }
    }

    fn evm_event_json_from_seed(seed: &str) -> String {
        // Generate a deterministic tx hash from the seed using keccak256
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(seed.as_bytes());
        let tx_hash_bytes = hasher.finalize().to_vec();

        let tx_hash = fixed_size::HexBinary::<32>::try_from(tx_hash_bytes).unwrap();
        let addr = fixed_size::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let ev = Event {
            contract_address: addr,
            event_index: 0,
            topics: vec![],
            data: HexBinary::from(Vec::<u8>::new()),
        };
        let evm = EvmEvent {
            transaction_hash: tx_hash,
            transaction_details: None,
            events: vec![ev],
        };
        serde_json::to_string(&EventData::Evm(evm)).unwrap()
    }

    /// Helper function to create a poll for an event and return the poll ID
    fn create_poll(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        event: &EventToVerify,
    ) -> PollId {
        let res = verify_events(deps.as_mut(), mock_env(), vec![event.clone()]).unwrap();
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));

        // Read the actual poll ID from state
        state::POLL_ID.cur(deps.as_ref().storage)
    }

    /// Helper function to create a poll, cast votes to reach consensus, and return the poll ID
    fn create_poll_and_vote_to_consensus(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        event: &EventToVerify,
        voting_verifiers: &[Verifier],
        vote: Vote,
    ) -> PollId {
        // Create a vector of the same vote for each verifier
        let votes = vec![vote; voting_verifiers.len()];

        // Use the more general helper function
        create_poll_and_cast_votes(deps, event, voting_verifiers, votes)
    }

    /// Helper function to create a poll and cast individual votes for each verifier
    fn create_poll_and_cast_votes(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        event: &EventToVerify,
        verifiers: &[Verifier],
        votes: Vec<Vote>,
    ) -> PollId {
        assert_eq!(
            verifiers.len(),
            votes.len(),
            "Must provide a vote for each verifier"
        );

        // Create poll
        let poll_id = create_poll(deps, event);

        // Cast votes for each verifier
        for (verifier, vote) in verifiers.iter().zip(votes.iter()) {
            execute::vote(
                deps.as_mut(),
                mock_env(),
                message_info(&verifier.address, &[]),
                poll_id,
                vec![vote.clone()],
            )
            .unwrap();
        }

        poll_id
    }
}
