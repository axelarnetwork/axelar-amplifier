use cosmwasm_std::{to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, WasmQuery};

use axelar_wasm_std::{snapshot, voting};
use connection_router::state::Message;
use service_registry::msg::{ActiveWorkers, QueryMsg};

use crate::error::ContractError;
use crate::events::PollStarted;
use crate::msg::VerifyMessagesResponse;
use crate::state::{CONFIG, PENDING_MESSAGES, POLLS, POLL_ID, VERIFIED_MESSAGES};

pub fn verify_messages(
    deps: DepsMut,
    env: Env,
    messages: Vec<Message>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // contract response, a vector of (message_id, is_verified) tuples
    let verification_statuses = messages
        .iter()
        .map(|message| {
            Ok((
                message.id.to_string(),
                is_message_verified(deps.as_ref(), message)?,
            ))
        })
        .collect::<Result<Vec<(String, bool)>, ContractError>>()?;

    let unverified_messages: Vec<&Message> = verification_statuses
        .iter()
        .zip(&messages)
        .filter_map(|(status, message)| {
            // already verified
            if status.1 {
                None
            } else {
                Some(message)
            }
        })
        .collect();

    if unverified_messages.is_empty() {
        return Ok(Response::new().set_data(to_binary(&VerifyMessagesResponse {
            verification_statuses,
        })?));
    }

    let snapshot = take_snapshot(deps.as_ref(), &env)?;
    let participants = snapshot.get_participants();

    let id = POLL_ID.incr(deps.storage)?;
    let poll = voting::WeightedPoll::new(
        id.into(),
        snapshot,
        env.block.height + config.block_expiry,
        unverified_messages.len(),
    );
    POLLS.save(deps.storage, id, &poll)?;

    let unverified_message_hashes = unverified_messages
        .iter()
        .map(|message| message.hash())
        .collect();
    PENDING_MESSAGES.save(deps.storage, id, &unverified_message_hashes)?;

    Ok(Response::new()
        .set_data(to_binary(&VerifyMessagesResponse {
            verification_statuses,
        })?)
        .add_event(
            PollStarted {
                poll_id: id.into(),
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                participants,
                messages: unverified_messages,
            }
            .into(),
        ))
}

pub fn vote(
    _deps: DepsMut,
    _info: MessageInfo,
    _poll_id: String,
    _votes: Vec<bool>,
) -> Result<Response, ContractError> {
    todo!()
}

pub fn end_poll(_deps: DepsMut, _poll_id: String) -> Result<Response, ContractError> {
    todo!()
}

fn take_snapshot(deps: Deps, env: &Env) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // todo: add chain param to query after service registry updated
    // query service registry for active workers
    let active_workers_query = QueryMsg::GetActiveWorkers {
        service_name: config.service_name,
    };

    let res: ActiveWorkers = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry.to_string(),
        msg: to_binary(&active_workers_query)?,
    }))?;

    let participants = res
        .workers
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

fn is_message_verified(deps: Deps, message: &Message) -> Result<bool, ContractError> {
    match VERIFIED_MESSAGES.may_load(deps.storage, &message.id)? {
        Some(hash) if hash != message.hash() => {
            Err(ContractError::MessageHashMismatch(message.id.to_string()))
        }
        Some(_) => Ok(true),
        None => Ok(false),
    }
}
