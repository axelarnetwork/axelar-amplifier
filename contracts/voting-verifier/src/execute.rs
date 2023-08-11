use connection_router::types::ChainName;
use cosmwasm_std::{
    to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, Storage, WasmQuery,
};

use axelar_wasm_std::voting::PollID;
use axelar_wasm_std::{
    snapshot,
    voting::{Poll, WeightedPoll},
};
use connection_router::state::Message;
use service_registry::msg::QueryMsg;
use service_registry::state::Worker;

use crate::error::ContractError;
use crate::events::{EvmMessages, MessageVerified, PollStarted, Voted};
use crate::msg::VerifyMessagesResponse;
use crate::state::{self, messages, TaggedMessage, CONFIG, POLLS, POLL_ID};

pub fn verify_messages(
    deps: DepsMut,
    env: Env,
    messages: Vec<Message>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let messages = messages
        .into_iter()
        .map(|message| {
            is_message_verified(deps.as_ref(), &env, &message).map(|status| (status, message))
        })
        .collect::<Result<Vec<(MessageStatus, Message)>, ContractError>>()?;

    let response = Response::new().set_data(to_binary(&VerifyMessagesResponse {
        verification_statuses: messages
            .iter()
            .map(|(status, message)| match status {
                MessageStatus::Verified => (message.id.to_string(), true),
                _ => (message.id.to_string(), false),
            })
            .collect(),
    })?);

    let to_verify: Vec<Message> = messages
        .into_iter()
        .filter_map(|(status, message)| match status {
            MessageStatus::NotVerified => Some(message),
            _ => None,
        })
        .collect();

    if to_verify.is_empty() {
        return Ok(response);
    }

    let snapshot = take_snapshot(deps.as_ref(), &env, &to_verify[0].source_chain)?;
    let participants = snapshot.get_participants();
    let id = create_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
        to_verify.len(),
    )?;

    for (idx, m) in to_verify.iter().enumerate() {
        state::messages().save(
            deps.storage,
            m.id.clone(),
            &TaggedMessage::new(m.clone(), id, idx as u32),
        )?;
    }

    let EvmMessages(source_chain, messages) = to_verify.try_into()?;

    Ok(response.add_event(
        PollStarted {
            poll_id: id,
            source_chain,
            source_gateway_address: config.source_gateway_address,
            confirmation_height: config.confirmation_height,
            expires_at: env.block.height + config.block_expiry,
            messages,
            participants,
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

    poll.cast_vote(env.block.height, &info.sender, votes)?;
    POLLS.save(deps.storage, poll_id, &poll)?;

    let mut evs = vec![];
    for idx in 0..poll.poll_size() {
        if poll.has_quorum(idx as u32)? {
            let msg = messages()
                .idx
                .polls
                .find_message(&deps, &poll_id, idx as u32)?
                .expect("could not find message matching poll and idx");
            evs.push(MessageVerified(msg).into());
        }
    }

    Ok(Response::new()
        .add_event(
            Voted {
                poll_id,
                voter: info.sender,
            }
            .into(),
        )
        .add_events(evs))
}

fn take_snapshot(
    deps: Deps,
    env: &Env,
    chain: &ChainName,
) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

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
        .map(service_registry::state::Worker::try_into)
        .collect::<Result<Vec<snapshot::Participant>, _>>()?;

    Ok(snapshot::Snapshot::new(
        env.block.time.try_into()?,
        env.block.height.try_into()?,
        config.voting_threshold,
        participants.try_into()?,
    ))
}

enum MessageStatus {
    Verified,
    NotVerified,
    Pending, // still in an open poll
}

fn is_message_verified(
    deps: Deps,
    env: &Env,
    message: &Message,
) -> Result<MessageStatus, ContractError> {
    match messages().may_load(deps.storage, message.id.clone())? {
        Some(tagged_msg) => {
            let poll = POLLS.load(deps.storage, tagged_msg.poll_id())?;
            if poll.has_quorum(tagged_msg.index_in_poll())? {
                if tagged_msg.message() != *message {
                    return Err(ContractError::MessageMismatch(message.id.to_string()));
                }
                Ok(MessageStatus::Verified)
            } else if poll.poll_finished(env.block.height) {
                Ok(MessageStatus::NotVerified)
            } else {
                Ok(MessageStatus::Pending)
            }
        }
        None => Ok(MessageStatus::NotVerified),
    }
}

fn create_poll(
    store: &mut dyn Storage,
    block_height: u64,
    expiry: u64,
    snapshot: snapshot::Snapshot,
    poll_size: usize,
) -> Result<PollID, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, block_height + expiry, poll_size);
    POLLS.save(store, id, &poll)?;

    Ok(id)
}
