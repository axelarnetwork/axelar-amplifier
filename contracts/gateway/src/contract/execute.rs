use cosmwasm_std::{to_binary, QueryRequest, WasmMsg, WasmQuery};
use error_stack::{Report, ResultExt};
use itertools::Itertools;

use connection_router::state::{CrossChainId, NewMessage};

use crate::{events::GatewayEvent, state::OUTGOING_MESSAGES};

use super::*;

pub fn verify_messages(
    deps: DepsMut,
    msgs: Vec<NewMessage>,
) -> error_stack::Result<Response, ContractError> {
    ensure_unique_ids(&msgs)?;

    let verifier = load_config(&deps)?.verifier;

    let (_, unverified) = partition_by_verified(deps, msgs).map_err(Report::from)?;

    Ok(Response::new().add_message(WasmMsg::Execute {
        contract_addr: verifier.to_string(),
        msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
            messages: unverified,
        })
        .map_err(ContractError::from)?,
        funds: vec![],
    }))
}

pub fn route_incoming_messages(
    deps: DepsMut,
    msgs: Vec<NewMessage>,
) -> error_stack::Result<Response, ContractError> {
    ensure_unique_ids(&msgs)?;

    let router = load_config(&deps)?.router;

    let (verified, unverified) = partition_by_verified(deps, msgs).map_err(Report::from)?;

    Ok(Response::new()
        .add_message(WasmMsg::Execute {
            contract_addr: router.to_string(),
            msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessages(
                verified.clone(),
            ))
            .map_err(ContractError::from)?,
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

fn partition_by_verified(
    deps: DepsMut,
    msgs: Vec<NewMessage>,
) -> error_stack::Result<(Vec<NewMessage>, Vec<NewMessage>), ContractError> {
    let verifier = load_config(&deps)?.verifier;

    let query_msg = aggregate_verifier::msg::QueryMsg::IsVerified {
        messages: msgs.clone(),
    };
    let query_response: Vec<(CrossChainId, bool)> = deps
        .querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: verifier.to_string(),
            msg: to_binary(&query_msg).map_err(ContractError::from)?,
        }))
        .map_err(ContractError::from)?;

    Ok(msgs.into_iter().partition(|msg| -> bool {
        match query_response.iter().find(|r| msg.cc_id == r.0) {
            Some((_, v)) => *v,
            None => false,
        }
    }))
}

fn load_config(deps: &DepsMut) -> error_stack::Result<Config, ContractError> {
    let cfg = CONFIG
        .load(deps.storage)
        .change_context(ContractError::ConfigNotFound)?;
    Ok(cfg)
}

fn ensure_unique_ids(msgs: &[NewMessage]) -> error_stack::Result<(), ContractError> {
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(|m| &m.cc_id)
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(ContractError::DuplicateMessageIds)
            .attach_printable(duplicates.iter().join(", "));
    }
    Ok(())
}
