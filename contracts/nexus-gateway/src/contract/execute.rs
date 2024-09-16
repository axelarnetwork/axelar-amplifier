use std::iter;

use axelar_core_std::nexus;
use axelar_wasm_std::token::GetToken;
use axelar_wasm_std::FnExt;
use cosmwasm_std::{BankMsg, Coin, CosmosMsg, MessageInfo, QuerierWrapper, Response, Storage};
use error_stack::{report, ResultExt};

use crate::error::Error;
use crate::state;
use crate::state::load_config;

type Result<T> = error_stack::Result<T, Error>;

pub fn route_messages_to_router(
    storage: &dyn Storage,
    msgs: Vec<nexus::execute::Message>,
) -> Result<Response<nexus::execute::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .map(router_api::Message::try_from)
        .collect::<error_stack::Result<Vec<_>, _>>()
        .change_context(Error::InvalidNexusMessageForRouter)?;

    let router = router_api::client::Router::new(state::load_config(storage)?.router);

    Ok(Response::new().add_messages(router.route(msgs)))
}

pub fn route_message_with_token_to_nexus(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    info: MessageInfo,
    msg: router_api::Message,
) -> Result<Response<nexus::execute::Message>> {
    let token = info
        .token()
        .change_context(Error::InvalidToken)?
        .ok_or(report!(Error::InvalidToken))?;

    route_message_to_nexus(storage, querier, msg, Some(token))?
        .then(|msgs| Response::new().add_messages(msgs))
        .then(Result::Ok)
}

pub fn route_messages_to_nexus(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    msgs: Vec<router_api::Message>,
) -> Result<Response<nexus::execute::Message>> {
    msgs.into_iter()
        .map(|msg| route_message_to_nexus(storage, querier, msg, None))
        .collect::<Result<Vec<_>>>()?
        .then(|msgs| msgs.concat())
        .then(|msgs| Response::new().add_messages(msgs))
        .then(Result::Ok)
}

fn route_message_to_nexus(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    msg: router_api::Message,
    token: Option<Coin>,
) -> Result<Vec<CosmosMsg<nexus::execute::Message>>> {
    if state::is_message_routed(storage, &msg.cc_id)? {
        return Ok(vec![]);
    }

    state::set_message_routed(storage, &msg.cc_id)?;

    let client: nexus::Client = client::CosmosClient::new(querier).into();
    let config = load_config(storage)?;

    let mut msg: nexus::execute::Message = msg.into();
    msg.token.clone_from(&token);

    token
        .into_iter()
        .map(|token| BankMsg::Send {
            to_address: config.nexus.to_string(),
            amount: vec![token],
        })
        .map(Into::into)
        .chain(iter::once(client.route_message(msg)))
        .collect::<Vec<_>>()
        .then(Result::Ok)
}
