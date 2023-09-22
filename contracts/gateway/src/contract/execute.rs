use connection_router::state::{CrossChainId, NewMessage};
use cosmwasm_std::{to_binary, QueryRequest, WasmMsg, WasmQuery};

use crate::{events::GatewayEvent, state::OUTGOING_MESSAGES};

use super::*;

fn contains_duplicates(msgs: &mut Vec<NewMessage>) -> bool {
    let orig_len = msgs.len();
    msgs.sort_unstable_by_key(|msg| msg.cc_id.to_string());
    msgs.dedup_by(|a, b| a.cc_id == b.cc_id);
    orig_len != msgs.len()
}

fn partition_by_verified(
    deps: DepsMut,
    msgs: Vec<NewMessage>,
) -> Result<(Vec<NewMessage>, Vec<NewMessage>), ContractError> {
    let verifier = CONFIG.load(deps.storage)?.verifier;

    let query_msg = aggregate_verifier::msg::QueryMsg::IsVerified {
        messages: msgs.clone(),
    };
    let query_response: Vec<(CrossChainId, bool)> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: verifier.to_string(),
            msg: to_binary(&query_msg)?,
        }))?;

    Ok(msgs.into_iter().partition(|msg| -> bool {
        match query_response.iter().find(|r| msg.cc_id == r.0) {
            Some((_, v)) => *v,
            None => false,
        }
    }))
}

pub fn verify_messages(
    deps: DepsMut,
    mut msgs: Vec<NewMessage>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let verifier = config.verifier;

    if contains_duplicates(&mut msgs) {
        return Err(ContractError::DuplicateMessageID);
    }

    let (_, unverified) = partition_by_verified(deps, msgs)?;

    Ok(Response::new().add_message(WasmMsg::Execute {
        contract_addr: verifier.to_string(),
        msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
            messages: unverified,
        })?,
        funds: vec![],
    }))
}

pub fn route_incoming_messages(
    deps: DepsMut,
    mut msgs: Vec<NewMessage>,
) -> Result<Response, ContractError> {
    let router = CONFIG.load(deps.storage)?.router;

    if contains_duplicates(&mut msgs) {
        return Err(ContractError::DuplicateMessageID);
    }

    let (verified, unverified) = partition_by_verified(deps, msgs.clone())?;

    Ok(Response::new()
        .add_message(WasmMsg::Execute {
            contract_addr: router.to_string(),
            msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessages(
                verified.clone(),
            ))?,
            funds: vec![],
        })
        .add_events(
            verified
                .into_iter()
                .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
        )
        .add_events(
            unverified
                .into_iter()
                .map(|msg| GatewayEvent::MessageRoutingFailed { msg }.into()),
        ))
}

pub fn route_outgoing_messages(
    deps: DepsMut,
    msgs: Vec<NewMessage>,
) -> Result<Response, ContractError> {
    for m in &msgs {
        OUTGOING_MESSAGES.save(deps.storage, m.cc_id.clone(), m)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
    ))
}
