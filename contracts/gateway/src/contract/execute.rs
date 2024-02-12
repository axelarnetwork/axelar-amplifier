use crate::contract::Error;
use crate::events::GatewayEvent;
use crate::router::Router;
use crate::state;
use crate::verifier::Verifier;
use axelar_wasm_std::utils::TryMapExt;
use axelar_wasm_std::VerificationStatus;
use connection_router::state::Message;
use cosmwasm_std::{Event, Response, Storage, WasmMsg};
use error_stack::{Result, ResultExt};
use itertools::Itertools;

pub fn verify_messages(verifier: &Verifier, msgs: Vec<Message>) -> Result<Response, Error> {
    let query_messages_status = |msg| verifier.messages_status(msg);

    let msgs_and_events = ignore_empty_msgs(msgs)
        .try_map(check_for_duplicates)?
        .try_map(query_messages_status)?
        .map(group_by_status)
        .into_iter()
        .flatten()
        .map(|(status, msgs)| do_verification(status, msgs, verifier));

    Ok(build_response(msgs_and_events))
}

pub(crate) fn route_incoming_messages(
    verifier: &Verifier,
    router: &Router,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    let query_messages_status = |msg| verifier.messages_status(msg);

    let msgs_and_events = ignore_empty_msgs(msgs)
        .try_map(check_for_duplicates)?
        .try_map(query_messages_status)?
        .map(group_by_status)
        .into_iter()
        .flatten()
        .map(|(status, msgs)| do_routing(status, msgs, router));

    Ok(build_response(msgs_and_events))
}

// because the messages came from the router, we can assume they are already verified
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified)?;

    for msg in msgs.iter() {
        state::save_outgoing_msg(store, msg.cc_id.clone(), msg)
            .change_context(Error::InvalidStoreAccess)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::Routing { msg }.into()),
    ))
}

fn group_by_status(
    msgs_with_status: impl Iterator<Item = (Message, VerificationStatus)>,
) -> impl Iterator<Item = (VerificationStatus, Vec<Message>)> {
    msgs_with_status
        .map(|(msg, status)| (status, msg))
        .into_group_map()
        .into_iter()
}

fn do_verification(
    status: VerificationStatus,
    msgs: Vec<Message>,
    verifier: &Verifier,
) -> (Option<WasmMsg>, Vec<Event>) {
    match status {
        VerificationStatus::None
        | VerificationStatus::NotFound
        | VerificationStatus::FailedToVerify => (
            Some(verifier.verify(msgs.clone())),
            messages_to_events(msgs, |msg| GatewayEvent::Verifying { msg }),
        ),
        VerificationStatus::InProgress => (
            None,
            messages_to_events(msgs, |msg| GatewayEvent::Verifying { msg }),
        ),
        VerificationStatus::SucceededOnChain => (
            None,
            messages_to_events(msgs, |msg| GatewayEvent::AlreadyVerified { msg }),
        ),
        VerificationStatus::FailedOnChain => (
            None,
            messages_to_events(msgs, |msg| GatewayEvent::AlreadyRejected { msg }),
        ),
    }
}

fn messages_to_events(msgs: Vec<Message>, transform: fn(Message) -> GatewayEvent) -> Vec<Event> {
    msgs.into_iter().map(|msg| transform(msg).into()).collect()
}

fn do_routing(
    status: VerificationStatus,
    msgs: Vec<Message>,
    router: &Router,
) -> (Option<WasmMsg>, Vec<Event>) {
    match status {
        VerificationStatus::SucceededOnChain => (
            Some(router.route_messages(msgs.clone())),
            messages_to_events(msgs, |msg| GatewayEvent::Routing { msg }),
        ),
        _ => (
            None,
            messages_to_events(msgs, |msg| GatewayEvent::UnfitForRouting { msg }),
        ),
    }
}

fn build_response(
    msgs_and_events: impl Iterator<Item = (Option<WasmMsg>, Vec<Event>)>,
) -> Response {
    msgs_and_events.fold(Response::new(), |response, (msg, events)| {
        let response = response.add_events(events);
        if let Some(msg) = msg {
            response.add_message(msg)
        } else {
            response
        }
    })
}

fn ignore_empty_msgs(msgs: Vec<Message>) -> Option<Vec<Message>> {
    if msgs.is_empty() {
        None
    } else {
        Some(msgs)
    }
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
