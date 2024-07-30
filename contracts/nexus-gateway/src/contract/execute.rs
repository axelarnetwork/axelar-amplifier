use cosmwasm_std::{to_json_binary, Response, Storage, WasmMsg};

use crate::error::ContractError;
use crate::{nexus, state};

type Result<T> = error_stack::Result<T, ContractError>;

pub fn route_to_router(
    storage: &dyn Storage,
    msgs: Vec<nexus::Message>,
) -> Result<Response<nexus::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .map(router_api::Message::try_from)
        .collect::<Result<Vec<_>>>()?;
    if msgs.is_empty() {
        return Ok(Response::default());
    }

    Ok(Response::new().add_message(WasmMsg::Execute {
        contract_addr: state::load_config(storage)?.router.to_string(),
        msg: to_json_binary(&router_api::msg::ExecuteMsg::RouteMessages(msgs))
            .expect("must serialize route-messages message"),
        funds: vec![],
    }))
}

pub fn route_to_nexus(
    storage: &mut dyn Storage,
    msgs: Vec<router_api::Message>,
) -> Result<Response<nexus::Message>> {
    let msgs = msgs
        .into_iter()
        .filter_map(|msg| match state::is_message_routed(storage, &msg.cc_id) {
            Ok(true) => None,
            Ok(false) => Some(Ok(msg)),
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>>>()?;

    msgs.iter()
        .try_for_each(|msg| state::set_message_routed(storage, &msg.cc_id))?;

    let msgs: Vec<nexus::Message> = msgs.into_iter().map(Into::into).collect();

    Ok(Response::new().add_messages(msgs))
}
