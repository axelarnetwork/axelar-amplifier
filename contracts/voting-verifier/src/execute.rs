use cosmwasm_std::{
    to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, Storage, WasmMsg, WasmQuery,
};

use axelar_wasm_std::{
    nonempty,
    operators::Operators,
    snapshot,
    voting::{PollId, Vote, WeightedPoll},
    VerificationStatus,
};

use connection_router::state::{ChainName, Message};
use service_registry::msg::QueryMsg;
use service_registry::state::Worker;

use crate::events::{
    PollEnded, PollMetadata, PollStarted, TxEventConfirmation, Voted, WorkerSetConfirmation,
};
use crate::msg::{EndPollResponse, VerifyMessagesResponse};
use crate::query::worker_set_status;
use crate::state::{self, Poll, PollContent, POLL_MESSAGES, POLL_WORKER_SETS};
use crate::state::{CONFIG, POLLS, POLL_ID};
use crate::{error::ContractError, query::message_status};

pub fn verify_worker_set(
    deps: DepsMut,
    env: Env,
    message_id: nonempty::String,
    new_operators: Operators,
) -> Result<Response, ContractError> {
    let status = worker_set_status(deps.as_ref(), &new_operators)?;
    if status.is_confirmed() {
        return Err(ContractError::WorkerSetAlreadyConfirmed);
    }

    let config = CONFIG.load(deps.storage)?;
    let snapshot = take_snapshot(deps.as_ref(), &config.source_chain)?;
    let participants = snapshot.get_participants();

    let poll_id = create_worker_set_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
    )?;

    POLL_WORKER_SETS.save(
        deps.storage,
        &new_operators.hash(),
        &PollContent::<Operators>::new(new_operators.clone(), poll_id),
    )?;

    Ok(Response::new().add_event(
        PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation::new(message_id, new_operators)?,
            metadata: PollMetadata {
                poll_id,
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
    if messages.is_empty() {
        Err(ContractError::EmptyMessages)?;
    }

    let source_chain = CONFIG.load(deps.storage)?.source_chain;

    if messages
        .iter()
        .any(|message| message.cc_id.chain.ne(&source_chain))
    {
        Err(ContractError::SourceChainMismatch(source_chain))?;
    }

    let config = CONFIG.load(deps.storage)?;

    let messages = messages
        .into_iter()
        .map(|message| message_status(deps.as_ref(), &message).map(|status| (status, message)))
        .collect::<Result<Vec<_>, _>>()?;

    let response = Response::new().set_data(to_binary(&VerifyMessagesResponse {
        verification_statuses: messages
            .iter()
            .map(|(status, message)| (message.cc_id.to_owned(), status.to_owned()))
            .collect(),
    })?);

    let msgs_to_verify: Vec<Message> = messages
        .into_iter()
        .filter_map(|(status, message)| match status {
            VerificationStatus::NotFound
            | VerificationStatus::FailedToVerify
            | VerificationStatus::None => Some(message),
            VerificationStatus::InProgress
            | VerificationStatus::SucceededOnChain
            | VerificationStatus::FailedOnChain => None,
        })
        .collect();

    if msgs_to_verify.is_empty() {
        return Ok(response);
    }

    let snapshot = take_snapshot(deps.as_ref(), &msgs_to_verify[0].cc_id.chain)?;
    let participants = snapshot.get_participants();
    let id = create_messages_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
        msgs_to_verify.len(),
    )?;

    for (idx, message) in msgs_to_verify.iter().enumerate() {
        POLL_MESSAGES.save(
            deps.storage,
            &message.hash(),
            &state::PollContent::<Message>::new(message.clone(), id, idx),
        )?;
    }

    let messages = msgs_to_verify
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<TxEventConfirmation>, _>>()?;

    Ok(response.add_event(
        PollStarted::Messages {
            messages,
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
    poll_id: PollId,
    votes: Vec<Vote>,
) -> Result<Response, ContractError> {
    let poll = POLLS
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound)?
        .try_map(|poll| {
            poll.cast_vote(env.block.height, &info.sender, votes)
                .map_err(ContractError::from)
        })?;

    POLLS.save(deps.storage, poll_id, &poll)?;

    Ok(Response::new().add_event(
        Voted {
            poll_id,
            voter: info.sender,
        }
        .into(),
    ))
}

pub fn end_poll(deps: DepsMut, env: Env, poll_id: PollId) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let poll = POLLS
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound)?
        .try_map(|poll| poll.finish(env.block.height).map_err(ContractError::from))?;

    POLLS.save(deps.storage, poll_id, &poll)?;

    let poll_result = match &poll {
        Poll::Messages(poll) | Poll::ConfirmWorkerSet(poll) => poll.state(),
    };

    // TODO: change rewards contract interface to accept a list of addresses to avoid creating multiple wasm messages
    let rewards_msgs = poll_result
        .consensus_participants
        .iter()
        .map(|address| WasmMsg::Execute {
            contract_addr: config.rewards_contract.to_string(),
            msg: to_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                event_id: poll_id
                    .to_string()
                    .try_into()
                    .expect("couldn't convert poll id to nonempty string"),
                worker_address: address.to_string(),
            })
            .expect("failed to serialize message for rewards contract"),
            funds: vec![],
        });

    Ok(Response::new()
        .add_messages(rewards_msgs)
        .add_event(
            PollEnded {
                poll_id: poll_result.poll_id,
                results: poll_result.results.clone(),
            }
            .into(),
        )
        .set_data(to_binary(&EndPollResponse { poll_result })?))
}

fn take_snapshot(deps: Deps, chain: &ChainName) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // todo: add chain param to query after service registry updated
    // query service registry for active workers
    let active_workers_query = QueryMsg::GetActiveWorkers {
        service_name: config.service_name.to_string(),
        chain_name: chain.clone(),
    };

    let workers: Vec<Worker> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry_contract.to_string(),
        msg: to_binary(&active_workers_query)?,
    }))?;

    let participants = workers
        .into_iter()
        .map(service_registry::state::Worker::try_into)
        .collect::<Result<Vec<snapshot::Participant>, _>>()?;

    Ok(snapshot::Snapshot::new(
        config.voting_threshold,
        participants.try_into()?,
    ))
}

fn create_worker_set_poll(
    store: &mut dyn Storage,
    block_height: u64,
    expiry: u64,
    snapshot: snapshot::Snapshot,
) -> Result<PollId, ContractError> {
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
) -> Result<PollId, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, block_height + expiry, poll_size);
    POLLS.save(store, id, &state::Poll::Messages(poll))?;

    Ok(id)
}
