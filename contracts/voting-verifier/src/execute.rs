use cosmwasm_std::{to_binary, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, WasmQuery};

use axelar_wasm_std::{snapshot, voting};
use connection_router::state::Message;
use service_registry::msg::{ActiveWorkers, QueryMsg};

use crate::error::ContractError;
use crate::events::PollStarted;
use crate::msg::VerifyMessagesResponse;
use crate::state::{PendingMessageID, CONFIG, PENDING_MESSAGES, POLLS, POLL_ID, VERIFIED_MESSAGES};

pub fn verify_messages(
    deps: DepsMut,
    env: Env,
    messages: Vec<Message>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    //  a vector of (message id, is verified) tuple
    let verification_statuses = messages
        .iter()
        .map(|message| {
            let is_verified = is_message_verified(&deps.as_ref(), message)?;
            Ok((message.id.to_string(), is_verified))
        })
        .collect::<Result<Vec<(String, bool)>, ContractError>>()?;

    if verification_statuses
        .iter()
        .all(|(_, is_verified)| *is_verified)
    {
        return Ok(Response::new().set_data(to_binary(&VerifyMessagesResponse {
            verification_statuses,
        })?));
    }

    let unverified_messages = filter_unverified_messages(&deps.as_ref(), messages)?;

    let snapshot = take_snapshot(&deps.as_ref(), &env)?;

    let id = POLL_ID.incr(deps.storage)?;
    let poll = voting::WeightedPoll::new(
        id.into(),
        snapshot.clone(),
        env.block.height + config.block_expiry,
        unverified_messages.len(),
    );
    POLLS.save(deps.storage, id, &poll)?;

    unverified_messages
        .iter()
        .enumerate()
        .try_for_each(|(i, message)| {
            let id = PendingMessageID {
                poll_id: id,
                index: i as u64,
            };
            PENDING_MESSAGES.save(deps.storage, &id, &message.hash())
        })?;

    Ok(Response::new()
        .set_data(to_binary(&VerifyMessagesResponse {
            verification_statuses,
        })?)
        .add_event(
            PollStarted {
                poll_id: id.into(),
                source_gateway_address: config.source_gateway_address,
                confirmation_height: config.confirmation_height,
                participants: snapshot.get_participants(),
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

fn is_message_verified(deps: &Deps, message: &Message) -> Result<bool, ContractError> {
    Ok(VERIFIED_MESSAGES
        .may_load(deps.storage, &message.hash())?
        .is_some())
}

fn take_snapshot(deps: &Deps, env: &Env) -> Result<snapshot::Snapshot, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // todo: add chain para to query after service registry updated
    // query service registry for active workers
    let active_workers_query: QueryMsg = QueryMsg::GetActiveWorkers {
        service_name: config.service_name,
    };

    let res: ActiveWorkers = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry_contract.to_string(),
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

fn filter_unverified_messages(
    deps: &Deps,
    messages: Vec<Message>,
) -> Result<Vec<Message>, ContractError> {
    Ok(messages
        .into_iter()
        .map(|msg| is_message_verified(deps, &msg).map(|v| (msg, v)))
        .collect::<Result<Vec<(Message, bool)>, _>>()?
        .into_iter()
        .filter_map(|(msg, is_verified)| if is_verified { Some(msg) } else { None })
        .collect())
}
