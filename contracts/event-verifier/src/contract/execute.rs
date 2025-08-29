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
use crate::events::{PollMetadata, PollStarted, QuorumReached, TxEventConfirmation, Voted};
use crate::state::{self, Poll, CONFIG, POLLS, POLL_ID, VOTES};
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
                &state::PollContent::<crate::msg::EventToVerify>::new(event.clone(), id, idx),
            )
            .change_context(ContractError::StorageError)?;
    }

    let event_confirmations = events_to_verify
        .iter()
        .map(|event| {
            // MessageIdFormat is no longer used in the implementation, so we can pass a dummy value
            TxEventConfirmation::try_from((event.clone(), &axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex))
                .map_err(|err| report!(err))
        })
        .collect::<Result<Vec<TxEventConfirmation>, _>>()?;

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

fn poll_results(poll: &Poll) -> PollResults {
    match poll {
        Poll::Events(weighted_poll) => weighted_poll.results(),
    }
}

fn make_quorum_event(
    vote: Option<Vote>,
    index_in_poll: u32,
    poll_id: &PollId,
    poll: &Poll,
    deps: &DepsMut,
) -> Result<Option<Event>, ContractError> {
    let status = vote.map(|vote| match vote {
        Vote::SucceededOnChain => VerificationStatus::SucceededOnSourceChain,
        Vote::FailedOnChain => VerificationStatus::FailedOnSourceChain,
        Vote::NotFound => VerificationStatus::NotFoundOnSourceChain,
    });

    match poll {
        Poll::Events(_) => {
            let event = state::poll_events()
                .idx
                .load_event(deps.storage, *poll_id, index_in_poll)
                .change_context(ContractError::StorageError)
                .expect("event not found in poll");

            Ok(status.map(|status| {
                QuorumReached {
                    content: event,
                    status,
                    poll_id: *poll_id,
                }
                .into()
            }))
        }
    }
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

    let poll = poll.try_map(|poll| {
        poll.cast_vote(env.block.height, &info.sender, votes.clone())
            .map_err(ContractError::from)
    })?;
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
        .save(store, id, &Poll::Events(poll))
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


