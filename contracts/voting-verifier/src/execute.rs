use cosmwasm_std::{to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, WasmQuery};

use axelar_wasm_std::{snapshot, voting};
use connection_router::state::Message;
use service_registry::msg::{ActiveWorkers, QueryMsg};

use crate::error::ContractError;
use crate::events::PollStarted;
use crate::execute::VerificationStatus::{Unverified, Verified};
use crate::msg::VerifyMessagesResponse;
use crate::state::{CONFIG, PENDING_MESSAGES, POLLS, POLL_ID, VERIFIED_MESSAGES};

enum VerificationStatus {
    Verified(Message),
    Unverified(Message),
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
                    Unverified(message)
                }
            })
        })
        .collect::<Result<Vec<VerificationStatus>, ContractError>>()?;

    let response = VerifyMessagesResponse {
        verification_statuses: messages
            .iter()
            .map(|status| match status {
                Verified(message) => (message.id.to_string(), true),
                Unverified(message) => (message.id.to_string(), false),
            })
            .collect(),
    };

    let messages: Vec<&Message> = messages
        .iter()
        .filter_map(|status| match status {
            Unverified(message) => Some(message),
            Verified(_) => None,
        })
        .collect();

    if messages.is_empty() {
        return Ok(Response::new().set_data(to_binary(&response)?));
    }

    let snapshot = take_snapshot(deps.as_ref(), &env)?;
    let participants = snapshot.get_participants();

    let id = POLL_ID.incr(deps.storage)?;
    let poll = voting::WeightedPoll::new(
        id.into(),
        snapshot,
        env.block.height + config.block_expiry,
        messages.len(),
    );
    POLLS.save(deps.storage, id, &poll)?;

    let hashes = messages.iter().map(|message| message.hash()).collect();
    PENDING_MESSAGES.save(deps.storage, id, &hashes)?;

    Ok(Response::new().set_data(to_binary(&response)?).add_event(
        PollStarted {
            poll_id: id.into(),
            source_gateway_address: config.source_gateway_address,
            confirmation_height: config.confirmation_height,
            participants,
            messages,
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
