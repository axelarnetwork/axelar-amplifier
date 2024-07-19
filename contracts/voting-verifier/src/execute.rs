use std::collections::HashMap;

use axelar_wasm_std::voting::{PollId, PollResults, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, snapshot, MajorityThreshold, VerificationStatus};
use cosmwasm_std::{
    to_json_binary, Addr, Deps, DepsMut, Env, Event, MessageInfo, OverflowError, OverflowOperation,
    QueryRequest, Response, Storage, WasmMsg, WasmQuery,
};
use itertools::Itertools;
use multisig::verifier_set::VerifierSet;
use router_api::{ChainName, Message};
use service_registry::msg::QueryMsg;
use service_registry::state::WeightedVerifier;

use crate::error::ContractError;
use crate::events::{
    PollEnded, PollMetadata, PollStarted, QuorumReached, TxEventConfirmation,
    VerifierSetConfirmation, Voted,
};
use crate::query::{message_status, verifier_set_status};
use crate::state::{
    self, poll_messages, poll_verifier_sets, Poll, PollContent, CONFIG, POLLS, POLL_ID, VOTES,
};

// TODO: this type of function exists in many contracts. Would be better to implement this
// in one place, and then just include it
pub fn require_governance(deps: &DepsMut, sender: Addr) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

pub fn update_voting_threshold(
    deps: DepsMut,
    new_voting_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    CONFIG.update(deps.storage, |mut config| -> Result<_, ContractError> {
        config.voting_threshold = new_voting_threshold;
        Ok(config)
    })?;
    Ok(Response::new())
}

pub fn verify_verifier_set(
    deps: DepsMut,
    env: Env,
    message_id: nonempty::String,
    new_verifier_set: VerifierSet,
) -> Result<Response, ContractError> {
    let status = verifier_set_status(deps.as_ref(), &new_verifier_set, env.block.height)?;
    if status.is_confirmed() {
        return Ok(Response::new());
    }

    let config = CONFIG.load(deps.storage)?;
    let snapshot = take_snapshot(deps.as_ref(), &config.source_chain)?;
    let participants = snapshot.get_participants();
    let expires_at = calculate_expiration(env.block.height, config.block_expiry)?;

    let poll_id = create_verifier_set_poll(deps.storage, expires_at, snapshot)?;

    poll_verifier_sets().save(
        deps.storage,
        &new_verifier_set.hash(),
        &PollContent::<VerifierSet>::new(new_verifier_set.clone(), poll_id),
    )?;

    Ok(Response::new().add_event(
        PollStarted::VerifierSet {
            verifier_set: VerifierSetConfirmation::new(
                message_id,
                config.msg_id_format,
                new_verifier_set,
            )?,
            metadata: PollMetadata {
                poll_id,
                source_chain: config.source_chain,
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                expires_at,
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
            message_status(deps.as_ref(), &message, env.block.height)
                .map(|status| (status, message))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let msgs_to_verify: Vec<Message> = messages
        .into_iter()
        .filter_map(|(status, message)| match status {
            VerificationStatus::NotFoundOnSourceChain
            | VerificationStatus::FailedToVerify
            | VerificationStatus::Unknown => Some(message),
            VerificationStatus::InProgress
            | VerificationStatus::SucceededOnSourceChain
            | VerificationStatus::FailedOnSourceChain => None,
        })
        .collect();

    if msgs_to_verify.is_empty() {
        return Ok(Response::new());
    }

    let snapshot = take_snapshot(deps.as_ref(), &msgs_to_verify[0].cc_id.chain)?;
    let participants = snapshot.get_participants();
    let expires_at = calculate_expiration(env.block.height, config.block_expiry)?;

    let id = create_messages_poll(deps.storage, expires_at, snapshot, msgs_to_verify.len())?;

    for (idx, message) in msgs_to_verify.iter().enumerate() {
        poll_messages().save(
            deps.storage,
            &message.hash(),
            &state::PollContent::<Message>::new(message.clone(), id, idx),
        )?;
    }

    let messages = msgs_to_verify
        .into_iter()
        .map(|msg| (msg, &config.msg_id_format).try_into())
        .collect::<Result<Vec<TxEventConfirmation>, _>>()?;

    Ok(Response::new().add_event(
        PollStarted::Messages {
            messages,
            metadata: PollMetadata {
                poll_id: id,
                source_chain: config.source_chain,
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                expires_at,
                participants,
            },
        }
        .into(),
    ))
}

fn get_poll_results(poll: &Poll) -> PollResults {
    match poll {
        Poll::Messages(weighted_poll) => weighted_poll.results(),
        Poll::ConfirmVerifierSet(weighted_poll) => weighted_poll.results(),
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
        Poll::Messages(_) => {
            let msg = poll_messages()
                .idx
                .load_message(deps.storage, *poll_id, index_in_poll)?
                .expect("message not found in poll");

            Ok(status.map(|status| {
                QuorumReached {
                    content: msg,
                    status,
                    poll_id: *poll_id,
                }
                .into()
            }))
        }
        Poll::ConfirmVerifierSet(_) => {
            let verifier_set = poll_verifier_sets()
                .idx
                .load_verifier_set(deps.storage, *poll_id)?
                .expect("verifier set not found in poll");

            Ok(status.map(|status| {
                QuorumReached {
                    content: verifier_set,
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
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound)?;

    let results_before_voting = get_poll_results(&poll);

    let poll = poll.try_map(|poll| {
        poll.cast_vote(env.block.height, &info.sender, votes.clone())
            .map_err(ContractError::from)
    })?;
    POLLS.save(deps.storage, poll_id, &poll)?;

    let results_after_voting = get_poll_results(&poll);

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

    VOTES.save(deps.storage, (poll_id, info.sender.to_string()), &votes)?;

    Ok(Response::new()
        .add_event(
            Voted {
                poll_id,
                voter: info.sender,
            }
            .into(),
        )
        .add_events(quorum_events.into_iter().flatten()))
}

pub fn end_poll(deps: DepsMut, env: Env, poll_id: PollId) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let poll = POLLS
        .may_load(deps.storage, poll_id)?
        .ok_or(ContractError::PollNotFound)?
        .try_map(|poll| poll.finish(env.block.height).map_err(ContractError::from))?;

    POLLS.save(deps.storage, poll_id, &poll)?;

    let votes: Vec<(String, Vec<Vote>)> = VOTES
        .prefix(poll_id)
        .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .try_collect()?;

    let poll_result = match &poll {
        Poll::Messages(poll) | Poll::ConfirmVerifierSet(poll) => {
            poll.state(HashMap::from_iter(votes))
        }
    };

    // TODO: change rewards contract interface to accept a list of addresses to avoid creating multiple wasm messages
    let rewards_msgs = poll_result
        .consensus_participants
        .iter()
        .map(|address| WasmMsg::Execute {
            contract_addr: config.rewards_contract.to_string(),
            msg: to_json_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                chain_name: config.source_chain.clone(),
                event_id: poll_id
                    .to_string()
                    .try_into()
                    .expect("couldn't convert poll id to nonempty string"),
                verifier_address: address.to_string(),
            })
            .expect("failed to serialize message for rewards contract"),
            funds: vec![],
        });

    Ok(Response::new().add_messages(rewards_msgs).add_event(
        PollEnded {
            poll_id: poll_result.poll_id,
            results: poll_result.results.0.clone(),
            source_chain: config.source_chain,
        }
        .into(),
    ))
}

fn take_snapshot(deps: Deps, chain: &ChainName) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // todo: add chain param to query after service registry updated
    // query service registry for active verifiers
    let active_verifiers_query = QueryMsg::GetActiveVerifiers {
        service_name: config.service_name.to_string(),
        chain_name: chain.clone(),
    };

    let verifiers: Vec<WeightedVerifier> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.service_registry_contract.to_string(),
            msg: to_json_binary(&active_verifiers_query)?,
        }))?;

    let participants = verifiers
        .into_iter()
        .map(WeightedVerifier::into)
        .collect::<Vec<snapshot::Participant>>();

    Ok(snapshot::Snapshot::new(
        config.voting_threshold,
        participants.try_into()?,
    ))
}

fn create_verifier_set_poll(
    store: &mut dyn Storage,
    expires_at: u64,
    snapshot: snapshot::Snapshot,
) -> Result<PollId, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, expires_at, 1);
    POLLS.save(store, id, &state::Poll::ConfirmVerifierSet(poll))?;

    Ok(id)
}

fn create_messages_poll(
    store: &mut dyn Storage,
    expires_at: u64,
    snapshot: snapshot::Snapshot,
    poll_size: usize,
) -> Result<PollId, ContractError> {
    let id = POLL_ID.incr(store)?;

    let poll = WeightedPoll::new(id, snapshot, expires_at, poll_size);
    POLLS.save(store, id, &state::Poll::Messages(poll))?;

    Ok(id)
}

fn calculate_expiration(block_height: u64, block_expiry: u64) -> Result<u64, ContractError> {
    block_height
        .checked_add(block_expiry)
        .ok_or_else(|| OverflowError::new(OverflowOperation::Add, block_height, block_expiry))
        .map_err(ContractError::from)
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;

    use super::require_governance;
    use crate::state::{Config, CONFIG};

    fn mock_config(governance: Addr, voting_threshold: MajorityThreshold) -> Config {
        Config {
            governance,
            service_registry_contract: Addr::unchecked("doesn't matter"),
            service_name: "validators".to_string().try_into().unwrap(),
            source_gateway_address: "0x89e51fA8CA5D66cd220bAed62ED01e8951aa7c40"
                .to_string()
                .try_into()
                .unwrap(),
            voting_threshold,
            source_chain: "ethereum".to_string().try_into().unwrap(),
            block_expiry: 10,
            confirmation_height: 2,
            rewards_contract: Addr::unchecked("rewards"),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        }
    }

    #[test]
    fn require_governance_should_reject_non_governance() {
        let mut deps = mock_dependencies();
        let governance = Addr::unchecked("governance");
        CONFIG
            .save(
                deps.as_mut().storage,
                &mock_config(
                    governance.clone(),
                    Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                ),
            )
            .unwrap();

        let res = require_governance(&deps.as_mut(), Addr::unchecked("random"));
        assert!(res.is_err());

        let res = require_governance(&deps.as_mut(), governance);
        assert!(res.is_ok());
    }
}
