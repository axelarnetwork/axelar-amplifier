use axelar_wasm_std::operators::Operators;
use cosmwasm_std::{
    to_binary, Addr, Deps, DepsMut, Env, MessageInfo, Order, QueryRequest, Response, Storage,
    WasmQuery,
};

use axelar_wasm_std::voting::{PollID, PollResult};
use axelar_wasm_std::{
    snapshot,
    voting::{Poll, WeightedPoll},
};
use connection_router::state::{ChainName, Message, MessageId};
use service_registry::msg::QueryMsg;
use service_registry::state::Worker;

use crate::error::ContractError;
use crate::events::{
    PollEnded, PollMetadata, PollStarted, TxEventConfirmation, Voted, WorkerSetConfirmation,
};
use crate::execute::VerificationStatus::{Pending, Verified};
use crate::msg::{EndPollResponse, VerifyMessagesResponse};
use crate::query::is_message_verified;
use crate::state;
use crate::state::{
    CONFIG, CONFIRMED_WORKER_SETS, PENDING_MESSAGES, PENDING_WORKER_SETS, POLLS, POLL_ID,
    VERIFIED_MESSAGES, VOTED,
};

enum VerificationStatus {
    Verified(Message),
    Pending(Message),
}

pub fn confirm_worker_set(
    deps: DepsMut,
    env: Env,
    message_id: MessageId,
    new_operators: Operators,
) -> Result<Response, ContractError> {
    if CONFIRMED_WORKER_SETS
        .may_load(deps.storage, new_operators.hash())?
        .is_some()
    {
        return Err(ContractError::WorkerSetAlreadyConfirmed);
    }

    let config = CONFIG.load(deps.storage)?;
    let snapshot = take_snapshot(deps.as_ref(), &env, &config.source_chain)?;
    let participants = snapshot.get_participants();

    let poll_id = create_worker_set_poll(
        deps.storage,
        env.block.height,
        config.block_expiry,
        snapshot,
    )?;

    PENDING_WORKER_SETS.save(deps.storage, poll_id, &new_operators)?;

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
                Verified(message) => (message.cc_id.clone(), true),
                Pending(message) => (message.cc_id.clone(), false),
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

    let snapshot = take_snapshot(deps.as_ref(), &env, &pending_messages[0].cc_id.chain)?;
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
        .collect::<Result<Vec<TxEventConfirmation>, _>>()?;

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
        .ok_or(ContractError::PollNotFound)?;

    match &mut poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
            cast_vote(deps.storage, env.block.height, poll, &info.sender, votes)?
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
            VERIFIED_MESSAGES.save(deps.storage, &message.cc_id, message)?;
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
        .ok_or(ContractError::PollNotFound)?;

    let poll_result = match &mut poll {
        state::Poll::Messages(poll) | state::Poll::ConfirmWorkerSet(poll) => {
            poll_result(deps.storage, env.block.height, poll)?
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
        service_name: config.service_name.to_string(),
        chain_name: chain.clone().into(),
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
        .ok_or(ContractError::PollNotFound)?;

    PENDING_MESSAGES.remove(store, poll_id);

    Ok(pending_messages)
}

fn cast_vote(
    store: &mut dyn Storage,
    block_height: u64,
    poll: &mut WeightedPoll,
    voter: &Addr,
    votes: Vec<bool>,
) -> Result<(), ContractError> {
    VOTED.update(
        store,
        (poll.poll_id, voter.clone()),
        |v| -> Result<(), ContractError> {
            match v {
                Some(_) => Err(ContractError::AlreadyVoted),
                None => {
                    poll.cast_vote(block_height, voter, votes)?;
                    Ok(())
                }
            }
        },
    )
}

fn poll_result(
    store: &mut dyn Storage,
    block_height: u64,
    poll: &mut WeightedPoll,
) -> Result<PollResult, ContractError> {
    let voters = VOTED
        .prefix(poll.poll_id)
        .range(store, None, None, Order::Ascending)
        .count();

    if block_height < poll.expires_at
            // can tally early if all participants voted
            && voters < poll.snapshot.get_participants().len()
    {
        return Err(ContractError::PollNotEnded);
    }

    Ok(poll.tally()?)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{nonempty, Participant, Snapshot, Threshold};
    use connection_router::state::CrossChainId;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Timestamp, Uint256, Uint64,
    };

    use super::*;

    fn new_poll(
        deps: DepsMut,
        expires_at: u64,
        poll_size: usize,
        participants: Vec<&str>,
        messages: &Vec<Message>,
    ) -> PollID {
        let participants: nonempty::Vec<Participant> = participants
            .into_iter()
            .map(|participant| Participant {
                address: Addr::unchecked(participant),
                weight: nonempty::Uint256::try_from(Uint256::from_u128(100)).unwrap(),
            })
            .collect::<Vec<Participant>>()
            .try_into()
            .unwrap();

        let timestamp: nonempty::Timestamp = Timestamp::from_nanos(1).try_into().unwrap();
        let height = nonempty::Uint64::try_from(Uint64::one()).unwrap();

        let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
        let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
        let threshold: Threshold = (numerator, denominator).try_into().unwrap();

        let snapshot = Snapshot::new(timestamp.clone(), height.clone(), threshold, participants);

        let poll = WeightedPoll::new(PollID::from(Uint64::one()), snapshot, expires_at, poll_size);
        let poll_id = poll.poll_id;

        POLLS
            .save(deps.storage, poll.poll_id, &state::Poll::Messages(poll))
            .unwrap();

        PENDING_MESSAGES
            .save(deps.storage, poll_id, messages)
            .unwrap();

        poll_id
    }

    #[test]
    fn voter_already_voted() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let expiry = 2;
        let poll_id = new_poll(
            deps.as_mut(),
            env.block.height + expiry,
            2,
            vec!["addr1", "addr2"],
            &vec![],
        );
        let votes = vec![true, true];

        vote(
            deps.as_mut(),
            env.clone(),
            mock_info("addr1", &[]),
            poll_id,
            votes.clone(),
        )
        .unwrap();

        assert_eq!(
            vote(
                deps.as_mut(),
                env.clone(),
                mock_info("addr1", &[]),
                poll_id,
                votes
            ),
            Err(ContractError::AlreadyVoted)
        );
    }

    #[test]
    fn poll_end_before_expiration() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let expiry = 2;
        let poll_id = new_poll(
            deps.as_mut(),
            env.block.height + expiry,
            1,
            vec!["addr1", "addr2"],
            &vec![Message {
                cc_id: CrossChainId {
                    id: "hash:index".parse().unwrap(),
                    chain: "chain".parse().unwrap(),
                },
                source_address: "source_address".parse().unwrap(),
                destination_chain: "destination_chain".parse().unwrap(),
                destination_address: "destination_address".parse().unwrap(),
                payload_hash: [1; 32].into(),
            }],
        );
        let votes = vec![true];

        assert_eq!(
            end_poll(deps.as_mut(), env, poll_id),
            Err(ContractError::PollNotEnded)
        );

        for voter in ["addr1", "addr2"] {
            vote(
                deps.as_mut(),
                mock_env(),
                mock_info(voter, &[]),
                poll_id,
                votes.clone(),
            )
            .unwrap();
        }

        end_poll(deps.as_mut(), mock_env(), poll_id).unwrap();
    }
}
