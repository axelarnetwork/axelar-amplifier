use std::collections::HashMap;


use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::voting::{PollId, PollResults, Vote, WeightedPoll};
use axelar_wasm_std::{snapshot, MajorityThreshold, VerificationStatus};
use cosmwasm_std::{
    Deps, DepsMut, Env, Event, MessageInfo, OverflowError, OverflowOperation, Response, Storage,
};
use error_stack::{report, Report, Result, ResultExt};
use crate::hash::hash_event_to_verify;
use itertools::Itertools;
use router_api::ChainName;
use service_registry::WeightedVerifier;

use crate::contract::query::event_status;
use crate::error::ContractError;
use crate::events::{EventConfirmation, PollMetadata, PollStarted, QuorumReached, Voted};
use crate::state::{self, CONFIG, POLLS, POLL_ID, VOTES};
use axelar_wasm_std::nonempty;

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

pub fn update_fee(
    deps: DepsMut,
    _info: MessageInfo,
    new_fee: cosmwasm_std::Coin,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage).expect("failed to load config");
    config.fee = new_fee;
    CONFIG
        .save(deps.storage, &config)
        .change_context(ContractError::StorageError)?;
    Ok(Response::new())
}

pub fn withdraw(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    receiver: nonempty::String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");

    let receiver = deps
        .api
        .addr_validate(&receiver)
        .change_context(ContractError::Unauthorized)?;

    let balance = deps
        .querier
        .query_balance(env.contract.address, config.fee.denom.clone())
        .map_err(ContractError::from)
        .map_err(Report::from)?;

    if balance.amount.is_zero() {
        return Ok(Response::new());
    }

    let send = cosmwasm_std::BankMsg::Send {
        to_address: receiver.to_string(),
        amount: vec![balance],
    };

    Ok(Response::new().add_message(send))
}

pub fn verify_events(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    events: Vec<crate::msg::EventToVerify>,
) -> Result<Response, ContractError> {
    if events.is_empty() {
        return Err(report!(ContractError::EmptyEvents));
    }

    let config = CONFIG.load(deps.storage).expect("failed to load config");

    let events = events.try_map(|event| {
        event_status(deps.as_ref(), &event, env.block.height).map(|status| (status, event))
    })?;

    let events_to_verify: Vec<crate::msg::EventToVerify> = events
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

    // Check fee
    if !config.fee.amount.is_zero() {
        let provided = info
            .funds
            .iter()
            .find(|c| c.denom == config.fee.denom)
            .map(|c| c.amount)
            .unwrap_or_default();
        if provided < config.fee.amount {
            return Err(report!(ContractError::InsufficientFee));
        }
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

    let event_confirmations = events_to_verify
        .iter()
        .map(|event| EventConfirmation::from(event.clone()))
        .collect::<Vec<EventConfirmation>>();

    Ok(Response::new().add_event(PollStarted::Events {
        events: event_confirmations,
        metadata: PollMetadata {
            poll_id: id,
            source_chain: source_chain.clone(),
            expires_at,
            participants,
        },
    }))
}

fn poll_results(poll: &WeightedPoll) -> PollResults { poll.results() }

fn make_quorum_event(
    vote: Option<Vote>,
    index_in_poll: u32,
    poll_id: &PollId,
    poll: &WeightedPoll,
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
        .change_context(ContractError::StorageError)
        .expect("event not found in poll");

    Ok(status.map(|status| {
        QuorumReached { content: event, status, poll_id: *poll_id }.into()
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
        .add_event(Voted {
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
    use crate::msg::{EventStatus, EventToVerify, ExecuteMsg, InstantiateMsg, QueryMsg};
    use axelar_wasm_std::{nonempty, MajorityThreshold};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{coin, from_json, Empty, OwnedDeps, Uint128, WasmQuery, HexBinary, Fraction};
    use router_api::ChainName;
    use service_registry::{AuthorizationState, BondingState, Verifier, WeightedVerifier};
    use axelar_wasm_std::fixed_size;
    use event_verifier_api::{EventData, EvmEvent, Event};
    use axelar_wasm_std::Threshold;
    use cosmwasm_std::to_json_binary;
    use cosmwasm_std::{CosmosMsg, BankMsg, coins};

    const SERVICE_REGISTRY_ADDRESS: &str = "service_registry_address";
    const SERVICE_NAME: &str = "service_name";
    const GOVERNANCE: &str = "governance";


    fn initial_voting_threshold() -> MajorityThreshold {
        Threshold::try_from((2, 3)).unwrap().try_into().unwrap()
    }

    fn verifiers(num: usize) -> Vec<Verifier> {
        (0..num)
            .map(|i| Verifier {
                address: MockApi::default().addr_make(format!("addr{}", i).as_str()),
                bonding_state: BondingState::Bonded { amount: Uint128::from(100u128).try_into().unwrap() },
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
                block_expiry: 100u64.try_into().unwrap(),
                fee: coin(0, "uaxl"),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. } if contract_addr == service_registry.as_str() => {
                Ok(to_json_binary(
                    &verifiers
                        .clone()
                        .into_iter()
                        .map(|v| WeightedVerifier { verifier_info: v, weight: nonempty::Uint128::one() })
                        .collect::<Vec<WeightedVerifier>>(),
                )
                .into())
                .into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    fn evm_event_json() -> String {
        let tx_hash = fixed_size::HexBinary::<32>::try_from(vec![0u8; 32]).unwrap();
        let addr = fixed_size::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let ev = Event { contract_address: addr, event_index: 0, topics: vec![], data: HexBinary::from(Vec::<u8>::new()) };
        let evm = EvmEvent { transaction_hash: tx_hash, transaction_details: None, events: vec![ev] };
        serde_json::to_string(&EventData::Evm(evm)).unwrap()
    }

    fn evm_event_json_with_index(index: u64) -> String {
        let tx_hash = fixed_size::HexBinary::<32>::try_from(vec![0u8; 32]).unwrap();
        let addr = fixed_size::HexBinary::<20>::try_from(vec![0u8; 20]).unwrap();
        let ev = Event { contract_address: addr, event_index: index, topics: vec![], data: HexBinary::from(Vec::<u8>::new()) };
        let evm = EvmEvent { transaction_hash: tx_hash, transaction_details: None, events: vec![ev] };
        serde_json::to_string(&EventData::Evm(evm)).unwrap()
    }

    fn event(chain: &str) -> EventToVerify {
        EventToVerify { source_chain: chain.parse().unwrap(), event_data: evm_event_json() }
    }

    fn event_with_index(chain: &str, index: u64) -> EventToVerify {
        EventToVerify { source_chain: chain.parse().unwrap(), event_data: evm_event_json_with_index(index) }
    }

    #[test]
    fn verify_events_should_error_on_invalid_input() {
        let mut deps = setup(verifiers(2));
        let api = deps.api;

        // empty events
        let err = verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![])
            .unwrap_err();
        assert_eq!(err.to_string(), ContractError::EmptyEvents.to_string());

        // mixed source chains
        let err = verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("s"), &[]),
            vec![event("chain-a"), event("chain-b")],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::SourceChainMismatch("chain-a".parse().unwrap()).to_string());

        // insufficient fee
        update_fee(deps.as_mut(), message_info(&api.addr_make("any"), &[]), coin(2, "uaxl")).unwrap();
        let err = verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("s"), &[]),
            vec![event("chain-a")],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::InsufficientFee.to_string());
    }

    #[test]
    fn reverify_only_allowed_statuses() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;
        let ev = event("chain-a");

        // Unknown -> should be verified (creates poll)
        let res = verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev.clone()]).unwrap();
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));

        // InProgress -> should NOT be re-verified
        let res = verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev.clone()])
            .unwrap();
        assert!(res.events.is_empty());

        // Advance to expiry -> FailedToVerify -> should be re-verified
        let mut env = mock_env();
        env.block.height += 100; // equals block_expiry
        let res = verify_events(deps.as_mut(), env, message_info(&api.addr_make("s"), &[]), vec![ev.clone()])
            .unwrap();
        // A new poll should be started
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));

        // Cast votes to SucceededOnChain -> should NOT be re-verified
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();

        let res = verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev.clone()])
            .unwrap();
        assert!(res.events.is_empty());

        // Create NotFound consensus for a fresh poll -> allowed to re-verify
        // Start fresh event/poll
        let ev2 = event("chain-a");
        verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev2.clone()]).unwrap();
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            2u64.into(),
            vec![Vote::NotFound],
        )
        .unwrap();
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            2u64.into(),
            vec![Vote::NotFound],
        )
        .unwrap();

        let res = verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev2.clone()])
            .unwrap();
        assert!(res.events.iter().any(|e| e.ty == "events_poll_started"));
    }

    #[test]
    fn votes_progress_status_and_quorum_reflects_votes() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;
        let ev = event("chain-a");

        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::Unknown);

        // Start poll
        verify_events(deps.as_mut(), mock_env(), message_info(&api.addr_make("s"), &[]), vec![ev.clone()]).unwrap();

        // Status should be InProgress
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // One vote not enough for quorum
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::FailedOnChain],
        )
        .unwrap();
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // Two votes, enough for quorum, but they differ, so no quorum yet
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // Reach quorum with two votes SucceededOnChain (third participant)
        execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr2"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::SucceededOnSourceChain);
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
        let mut deps = setup(verifiers(1));
        let api = deps.api;
        // create a poll with single event
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&MockApi::default().addr_make("starter"), &[]),
            vec![event("chain-a")],
        ));

        // cast vote from non-participant
        let err = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-in-set"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::VoteError(axelar_wasm_std::voting::Error::NotParticipant).to_string());
    }

    #[test]
    fn vote_should_error_when_already_voted() {
        let mut deps = setup(verifiers(2));
        let api = deps.api;
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&MockApi::default().addr_make("starter"), &[]),
            vec![event("chain-a")],
        ));

        // first vote ok
        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::FailedOnChain],
        ));

        // second vote by same participant should fail
        let err = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::FailedOnChain],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::VoteError(axelar_wasm_std::voting::Error::AlreadyVoted).to_string());
    }

    #[test]
    fn vote_should_record_votes_in_state() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&MockApi::default().addr_make("starter"), &[]),
            vec![event("chain-a")],
        ));

        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::NotFound],
        ));
        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));

        // Verify that VOTES map recorded the per-voter votes correctly
        use crate::state::VOTES;
        let addr0 = api.addr_make("addr0").to_string();
        let addr1 = api.addr_make("addr1").to_string();
        let v0 = assert_ok!(VOTES.load(deps.as_ref().storage, (1u64.into(), addr0)));
        let v1 = assert_ok!(VOTES.load(deps.as_ref().storage, (1u64.into(), addr1)));
        assert_eq!(v0, vec![Vote::NotFound]);
        assert_eq!(v1, vec![Vote::SucceededOnChain]);

        // Also check tallies/consensus reflects votes progression
        // After one NotFound and one SucceededOnChain, no consensus yet
        let poll = POLLS.load(deps.as_ref().storage, 1u64.into()).unwrap();
        let results = poll.results();
        assert!(results.0[0].is_none());

        // Third vote NotFound should make consensus NotFound (2/3)
        assert_ok!(vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr2"), &[]),
            1u64.into(),
            vec![Vote::NotFound],
        ));
        let poll = POLLS.load(deps.as_ref().storage, 1u64.into()).unwrap();
        let results = poll.results();
        assert_eq!(results.0[0], Some(Vote::NotFound));
    }

    #[test]
    fn poll_created_correctly_in_state() {
        // Build verifier set once and reuse for instantiation and assertions
        let addrs = ["addr0", "addr1", "addr2"]; 
        let verifiers = addrs
            .iter()
            .map(|name| Verifier {
                address: MockApi::default().addr_make(name),
                bonding_state: BondingState::Bonded { amount: Uint128::from(100u128).try_into().unwrap() },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
            .collect::<Vec<_>>();

        let mut deps = setup(verifiers.clone());

        // two distinct events on same chain
        let ev1 = event_with_index("chain-a", 0);
        let ev2 = event_with_index("chain-a", 1);

        // create poll
        let starter = MockApi::default().addr_make("starter");
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&starter, &[]),
            vec![ev1.clone(), ev2.clone()],
        ));

        // poll stored with id=1
        let poll = POLLS.load(deps.as_ref().storage, 1u64.into()).unwrap();
        assert_eq!(poll.poll_id, 1u64.into());
        assert_eq!(poll.poll_size, 2);
        // not finished yet, height 0 => InProgress
        assert!(matches!(poll.status(0), axelar_wasm_std::voting::PollStatus::InProgress));

        // participants match service registry verifiers
        let part_keys: Vec<String> = poll.participation.keys().cloned().collect();
        let expected_addrs_from_verifiers: Vec<String> = verifiers.iter().map(|v| v.address.to_string()).collect();
        assert_eq!(part_keys.len(), expected_addrs_from_verifiers.len());
        for addr in expected_addrs_from_verifiers {
            let p = poll.participation.get(&addr).expect("participant missing");
            assert_eq!(p.weight, nonempty::Uint128::one());
            assert!(!p.voted);
        }

        // events indexed under poll id
        let stored_events = state::poll_events().idx.load_events(deps.as_ref().storage, 1u64.into()).unwrap();
        assert_eq!(stored_events.len(), 2);
        assert_eq!(stored_events[0], ev1);
        assert_eq!(stored_events[1], ev2);
    }

    #[test]
    fn threshold_update_is_respected() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;

        // Update threshold from initial 2/3 to 3/3
        let three_of_three: MajorityThreshold = axelar_wasm_std::Threshold::try_from((3u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        assert_ok!(update_voting_threshold(deps.as_mut(), three_of_three));

        // Create a poll with one event
        let ev = event("chain-a");
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&MockApi::default().addr_make("starter"), &[]),
            vec![ev.clone()],
        ));

        // Two votes should NOT reach quorum under 3/3
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::InProgress);

        // Third vote should reach quorum under 3/3 and succeed
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr2"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));
        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::SucceededOnSourceChain);
    }

    #[test]
    fn threshold_update_only_applies_to_new_polls() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;

        // Create poll under initial 2/3 threshold
        let ev = event("chain-a");
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&MockApi::default().addr_make("starter"), &[]),
            vec![ev.clone()],
        ));

        // Update threshold to 3/3 for NEW polls
        let three_of_three: MajorityThreshold = axelar_wasm_std::Threshold::try_from((3u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap();
        assert_ok!(update_voting_threshold(deps.as_mut(), three_of_three));

        // For existing poll (id=1), 2 votes should still reach quorum (old 2/3 threshold)
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));
        assert_ok!(execute::vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        ));

        let res = query::events_status(deps.as_ref(), &vec![ev.clone()], mock_env().block.height).unwrap();
        assert_eq!(res[0].status, VerificationStatus::SucceededOnSourceChain);
    }

    #[test]
    fn fee_mechanics_are_enforced() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;

        // Update fee to 2 uaxl
        assert_ok!(update_fee(
            deps.as_mut(),
            message_info(&api.addr_make("any"), &[]),
            coin(2, "uaxl"),
        ));

        // Insufficient funds (1 < 2) should be rejected
        let err = verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("caller"), &coins(1, "uaxl")),
            vec![event("chain-a")],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), ContractError::InsufficientFee.to_string());
    }

    #[test]
    fn withdraw_sends_full_balance_to_receiver() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;

        // Attach funds in a verify call; in mocks we also credit the contract balance
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("payer"), &coins(7, "uaxl")),
            vec![event("chain-a")],
        ));
        let env = mock_env();
        let contract_addr = env.contract.address.clone();
        deps.querier.bank.update_balance(contract_addr.clone(), coins(7, "uaxl"));

        let receiver = api.addr_make("rcv").as_str().parse().unwrap();
        let resp = withdraw(
            deps.as_mut(),
            env.clone(),
            message_info(&api.addr_make("admin"), &[]),
            receiver,
        )
        .unwrap();

        assert_eq!(resp.messages.len(), 1);
        match &resp.messages[0].msg {
            CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
                assert_eq!(to_address, &api.addr_make("rcv").to_string());
                assert_eq!(amount, &coins(7, "uaxl"));
            }
            _ => panic!("expected bank send"),
        }
    }

    #[test]
    fn quorum_reached_event_emitted_exactly_on_quorum() {
        let mut deps = setup(verifiers(3));
        let api = deps.api;

        // Create poll with one event
        assert_ok!(verify_events(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("starter"), &[]),
            vec![event("chain-a")],
        ));

        // First vote: no quorum yet, no quorum_reached event
        let res1 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr0"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(!res1.events.iter().any(|e| e.ty == "quorum_reached"));

        // Second vote: reaches quorum, exactly one quorum_reached event emitted
        let res2 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr1"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(res2.events.iter().any(|e| e.ty == "quorum_reached"));

        // Third vote: already at quorum; no new quorum_reached events
        let res3 = vote(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("addr2"), &[]),
            1u64.into(),
            vec![Vote::SucceededOnChain],
        )
        .unwrap();
        assert!(!res3.events.iter().any(|e| e.ty == "quorum_reached"));
    }
}

