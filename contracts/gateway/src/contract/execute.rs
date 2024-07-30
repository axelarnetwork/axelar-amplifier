use axelar_wasm_std::{FnExt, VerificationStatus};
use cosmwasm_std::{Event, Response, Storage, WasmMsg};
use error_stack::{report, Result, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::Message;
use voting_verifier::msg::MessageStatus;

use crate::contract::Error;
use crate::events::GatewayEvent;
use crate::state;

pub fn verify_messages(
    verifier: &voting_verifier::Client,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    apply(verifier, msgs, |msgs_by_status| {
        verify(verifier, msgs_by_status)
    })
}

pub(crate) fn route_incoming_messages(
    verifier: &voting_verifier::Client,
    router: &Router,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    apply(verifier, msgs, |msgs_by_status| {
        route(router, msgs_by_status)
    })
}

// because the messages came from the router, we can assume they are already verified
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified)?;

    for msg in msgs.iter() {
        state::OUTGOING_MESSAGES
            .may_load(store, &msg.cc_id)
            .change_context(Error::InvalidStoreAccess)
            .and_then(|stored_msg| match stored_msg {
                Some(stored_msg) if msg.hash() != stored_msg.hash() => {
                    Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
                }
                Some(_) => Ok(()), // message already exists
                None => state::OUTGOING_MESSAGES
                    .save(store, &msg.cc_id, msg)
                    .change_context(Error::InvalidStoreAccess),
            })?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::Routing { msg }.into()),
    ))
}

fn apply(
    verifier: &voting_verifier::Client,
    msgs: Vec<Message>,
    action: impl Fn(Vec<(VerificationStatus, Vec<Message>)>) -> (Option<WasmMsg>, Vec<Event>),
) -> Result<Response, Error> {
    check_for_duplicates(msgs)?
        .then(|msgs| verifier.messages_status(msgs))
        .change_context(Error::MessageStatus)?
        .then(group_by_status)
        .then(action)
        .then(|(msgs, events)| Response::new().add_messages(msgs).add_events(events))
        .then(Ok)
}

fn check_for_duplicates(msgs: Vec<Message>) -> Result<Vec<Message>, Error> {
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(|m| &m.cc_id)
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(Error::DuplicateMessageIds).attach_printable(duplicates.iter().join(", "));
    }
    Ok(msgs)
}

fn group_by_status(
    msgs_with_status: impl IntoIterator<Item = MessageStatus>,
) -> Vec<(VerificationStatus, Vec<Message>)> {
    msgs_with_status
        .into_iter()
        .map(|msg_status| (msg_status.status, msg_status.message))
        .into_group_map()
        .into_iter()
        // sort by verification status so the order of messages is deterministic
        .sorted_by_key(|(status, _)| *status)
        .collect()
}

fn verify(
    verifier: &voting_verifier::Client,
    msgs_by_status: Vec<(VerificationStatus, Vec<Message>)>,
) -> (Option<WasmMsg>, Vec<Event>) {
    msgs_by_status
        .into_iter()
        .map(|(status, msgs)| {
            (
                filter_verifiable_messages(status, &msgs),
                into_verify_events(status, msgs),
            )
        })
        .then(flat_unzip)
        .then(|(msgs, events)| (verifier.verify_messages(msgs), events))
}

fn route(
    router: &Router,
    msgs_by_status: Vec<(VerificationStatus, Vec<Message>)>,
) -> (Option<WasmMsg>, Vec<Event>) {
    msgs_by_status
        .into_iter()
        .map(|(status, msgs)| {
            (
                filter_routable_messages(status, &msgs),
                into_route_events(status, msgs),
            )
        })
        .then(flat_unzip)
        .then(|(msgs, events)| (router.route(msgs), events))
}

// not all messages are verifiable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_verifiable_messages(status: VerificationStatus, msgs: &[Message]) -> Vec<Message> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify => msgs.to_vec(),
        _ => vec![],
    }
}

fn into_verify_events(status: VerificationStatus, msgs: Vec<Message>) -> Vec<Event> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify
        | VerificationStatus::InProgress => {
            messages_into_events(msgs, |msg| GatewayEvent::Verifying { msg })
        }
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyVerified { msg })
        }
        VerificationStatus::FailedOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyRejected { msg })
        }
    }
}

// not all messages are routable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_routable_messages(status: VerificationStatus, msgs: &[Message]) -> Vec<Message> {
    if status == VerificationStatus::SucceededOnSourceChain {
        msgs.to_vec()
    } else {
        vec![]
    }
}

fn into_route_events(status: VerificationStatus, msgs: Vec<Message>) -> Vec<Event> {
    match status {
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::Routing { msg })
        }
        _ => messages_into_events(msgs, |msg| GatewayEvent::UnfitForRouting { msg }),
    }
}

fn flat_unzip<A, B>(x: impl Iterator<Item = (Vec<A>, Vec<B>)>) -> (Vec<A>, Vec<B>) {
    let (x, y): (Vec<_>, Vec<_>) = x.unzip();
    (
        x.into_iter().flatten().collect(),
        y.into_iter().flatten().collect(),
    )
}

fn messages_into_events(msgs: Vec<Message>, transform: fn(Message) -> GatewayEvent) -> Vec<Event> {
    msgs.into_iter().map(|msg| transform(msg).into()).collect()
}
