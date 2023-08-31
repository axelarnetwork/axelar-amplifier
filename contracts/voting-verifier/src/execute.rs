use axelar_wasm_std::operators::Operators;
use connection_router::types::{ChainName, MessageID};
use cosmwasm_std::{
    to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, Storage, WasmQuery,
};

use axelar_wasm_std::voting::{PollID, PollResult};
use axelar_wasm_std::{
    snapshot,
    voting::{Poll, WeightedPoll},
};
use connection_router::state::Message;
use service_registry::msg::QueryMsg;
use service_registry::state::Worker;

use crate::error::ContractError;
use crate::events::{
    EvmMessage, PollEnded, PollMetadata, PollStarted, Voted, WorkerSetConfirmation,
};
use crate::execute::VerificationStatus::{Pending, Verified};
use crate::msg::{EndPollResponse, VerifyMessagesResponse};
use crate::query::is_message_verified;
use crate::state;
use crate::state::{
    CONFIG, CONFIRMED_WORKER_SETS, PENDING_MESSAGES, PENDING_WORKER_SETS, POLLS, POLL_ID,
    VERIFIED_MESSAGES,
};

enum VerificationStatus {
    Verified(Message),
    Pending(Message),
}

pub fn confirm_worker_set(
    deps: DepsMut,
    env: Env,
    message_id: MessageID,
    new_operators: Operators,
) -> Result<Response, ContractError> {
    if CONFIRMED_WORKER_SETS
        .may_load(deps.storage, new_operators.hash())?
        .is_some()
    {
        return Err(ContractError::WorkerSetAlreadyConfirmed {});
    }

    let config = CONFIG.load(deps.storage)?;
    let snapshot = take_snapshot(deps.as_ref(), &env, &config.source_chain)?;
    let participants = snapshot.get_participants();

    let id = create_worker_set_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
    )?;

    PENDING_WORKER_SETS.save(deps.storage, id, &new_operators)?;

    Ok(Response::new().add_event(
        PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation::new(message_id, new_operators)?,
            metadata: PollMetadata {
                poll_id: id,
                source_chain: config.source_chain,
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                expires_at: env.block.height + config.block_expiry,
                participants,
            },
        }
        .into(),
    ))
}

pub fn verify_messages(
    deps: DepsMut,
    env: Env,
    messages: Vec<Message>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let messages = messages
        .into_iter()
        .map(|message| {
            is_message_verified(deps.as_ref(), &message).map(|verified| {
                if verified {
                    Verified(message)
                } else {
                    Pending(message)
                }
            })
        })
        .collect::<Result<Vec<VerificationStatus>, ContractError>>()?;

    let response = Response::new().set_data(to_binary(&VerifyMessagesResponse {
        verification_statuses: messages
            .iter()
            .map(|status| match status {
                Verified(message) => (message.id.to_string(), true),
                Pending(message) => (message.id.to_string(), false),
            })
            .collect(),
    })?);

    let pending_messages: Vec<Message> = messages
        .into_iter()
        .filter_map(|status| match status {
            Pending(message) => Some(message),
            Verified(_) => None,
        })
        .collect();

    if pending_messages.is_empty() {
        return Ok(response);
    }

    let snapshot = take_snapshot(deps.as_ref(), &env, &pending_messages[0].source_chain)?;
    let participants = snapshot.get_participants();
    let id = create_messages_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
        pending_messages.len(),
    )?;

    PENDING_MESSAGES.save(deps.storage, id, &pending_messages)?;

    let evm_messages = pending_messages
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<EvmMessage>, _>>()?;

    Ok(response.add_event(
        PollStarted::Messages {
            messages: evm_messages,
            metadata: PollMetadata {
                poll_id: id,
                source_chain: config.source_chain,
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                expires_at: env.block.height + config.block_expiry,
                participants,
            },
        }
        .into(),
    ))
}

pub fn vote(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    poll_id: PollID,
    votes: Vec<bool>,
) -> Result<Response, ContractError> {
    let mut poll = POLLS
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound {})?;
    match &mut poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
            poll.cast_vote(env.block.height, &info.sender, votes)?
        }
    };

    POLLS.save(deps.storage, poll_id, &poll)?;

    Ok(Response::new().add_event(
        Voted {
            poll_id,
            voter: info.sender,
        }
        .into(),
    ))
}

fn end_poll_messages(
    deps: DepsMut,
    poll_id: PollID,
    poll_result: &PollResult,
) -> Result<(), ContractError> {
    let messages = remove_pending_message(deps.storage, poll_id)?;

    assert_eq!(
        messages.len(),
        poll_result.results.len(),
        "poll {} results and pending messages have different length",
        poll_id
    );

    let messages = messages
        .iter()
        .zip(poll_result.results.iter())
        .filter_map(|(message, verified)| match *verified {
            true => Some(message),
            false => None,
        })
        .collect::<Vec<&Message>>();

    for message in messages {
        if !is_message_verified(deps.as_ref(), message)? {
            VERIFIED_MESSAGES.save(deps.storage, &message.id, message)?;
        }
    }

    Ok(())
}

fn end_poll_worker_set(
    deps: DepsMut,
    poll_id: PollID,
    poll_result: &PollResult,
) -> Result<(), ContractError> {
    assert_eq!(
        poll_result.results.len(),
        1,
        "poll {} results for worker set is not length 1",
        poll_id
    );

    let worker_set = PENDING_WORKER_SETS.load(deps.storage, poll_id)?;
    if poll_result.results[0] {
        CONFIRMED_WORKER_SETS.save(deps.storage, worker_set.hash(), &())?;
    }

    PENDING_WORKER_SETS.remove(deps.storage, poll_id);

    Ok(())
}

pub fn end_poll(deps: DepsMut, env: Env, poll_id: PollID) -> Result<Response, ContractError> {
    let mut poll = POLLS
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound {})?;

    let poll_result = match &mut poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
            poll.tally(env.block.height)?
        }
    };
    POLLS.save(deps.storage, poll_id, &poll)?;

    match poll {
        state::Poll::Messages(_) => {
            end_poll_messages(deps, poll_id, &poll_result)?;
        }
        state::Poll::ConfirmWorkerSet(_) => end_poll_worker_set(deps, poll_id, &poll_result)?,
    };

    Ok(Response::new()
        .add_event(
            PollEnded {
                poll_id: poll_result.poll_id,
                results: poll_result.results.clone(),
            }
            .into(),
        )
        .set_data(to_binary(&EndPollResponse { poll_result })?))
}

fn take_snapshot(
    deps: Deps,
    env: &Env,
    chain: &ChainName,
) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // todo: add chain param to query after service registry updated
    // query service registry for active workers
    let active_workers_query = QueryMsg::GetActiveWorkers {
        service_name: config.service_name,
        chain_name: chain.clone().into(),
    };

    let workers: Vec<Worker> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry.to_string(),
        msg: to_binary(&active_workers_query)?,
    }))?;

    let participants = workers
        .into_iter()
        .map(service_registry::state::Worker::into)
        .collect::<Vec<snapshot::NonWeightedParticipant>>();

    Ok(snapshot::Snapshot::new(
        env.block.time.try_into()?,
        env.block.height.try_into()?,
        config.voting_threshold,
        participants.try_into()?,
    ))
}

fn create_worker_set_poll(
    store: &mut dyn Storage,
    block_height: u64,
    expiry: u64,
    snapshot: snapshot::Snapshot,
) -> Result<PollID, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, block_height + expiry, 1);
    POLLS.save(store, id, &state::Poll::ConfirmWorkerSet(poll))?;

    Ok(id)
}

fn create_messages_poll(
    store: &mut dyn Storage,
    block_height: u64,
    expiry: u64,
    snapshot: snapshot::Snapshot,
    poll_size: usize,
) -> Result<PollID, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, block_height + expiry, poll_size);
    POLLS.save(store, id, &state::Poll::Messages(poll))?;

    Ok(id)
}

fn remove_pending_message(
    store: &mut dyn Storage,
    poll_id: PollID,
) -> Result<Vec<Message>, ContractError> {
    let pending_messages = PENDING_MESSAGES
        .may_load(store, poll_id)?
        .ok_or(ContractError::PollNotFound {})?;

    PENDING_MESSAGES.remove(store, poll_id);

    Ok(pending_messages)
}
