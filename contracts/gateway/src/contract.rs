#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, Reply, Response,
    StdError, StdResult, WasmMsg,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use crate::{
    error::ContractError,
    events::GatewayEvent,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Config, CACHED, CONFIG, OUTGOING_MESSAGES},
};

use connection_router::state::Message;

use self::execute::{route_incoming_messages, route_outgoing_messages, verify_messages};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let router = deps.api.addr_validate(&msg.router_address)?;
    let verifier = deps.api.addr_validate(&msg.verifier_address)?;

    CONFIG.save(deps.storage, &Config { verifier, router })?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages(messages) => {
            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;
            verify_messages(deps, msgs)
        }

        ExecuteMsg::RouteMessages(messages) => {
            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;

            let router = CONFIG.load(deps.storage)?.router;
            if info.sender == router {
                route_outgoing_messages(deps, msgs)
            } else {
                route_incoming_messages(deps, msgs)
            }
        }
    }
}

pub mod execute {

    use cosmwasm_std::{to_binary, Addr, SubMsg, WasmMsg};

    use crate::{
        events::GatewayEvent,
        state::{CallbackCache, CACHED, OUTGOING_MESSAGES},
    };

    use super::*;

    pub fn verify_messages(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
        let verifier = CONFIG.load(deps.storage)?.verifier;

        build_response_with_submessage(deps, msgs, verifier, REPLY_VERIFY)
    }

    pub fn route_incoming_messages(
        deps: DepsMut,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let verifier = config.verifier;

        build_response_with_submessage(deps, msgs, verifier, REPLY_ROUTE)
    }

    pub fn route_outgoing_messages(
        deps: DepsMut,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        for m in &msgs {
            OUTGOING_MESSAGES.save(deps.storage, m.id(), m)?;
        }

        Ok(Response::new().add_events(
            msgs.into_iter()
                .map(|m| GatewayEvent::MessageRouted { msg: m }.into()),
        ))
    }

    // *** Helper functions ***

    // builds the response, adding the appropriate submessages
    // stores the data that is needed for processing the submessage reply
    fn build_response_with_submessage(
        deps: DepsMut,
        mut msgs: Vec<Message>,
        verifier: Addr,
        submessage_id: u64,
    ) -> Result<Response, ContractError> {
        CACHED.save(
            deps.storage,
            &CallbackCache {
                messages: msgs.clone(),
            },
        )?;
        let orig_len = msgs.len();
        msgs.sort_unstable_by_key(|a| a.id());
        msgs.dedup_by(|a, b| a.id() == b.id());
        if msgs.len() != orig_len {
            return Err(ContractError::DuplicateMessageID {});
        }

        Ok(Response::new().add_submessage(SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: verifier.to_string(),
                msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
                    messages: msgs
                        .into_iter()
                        .map(connection_router::msg::Message::from)
                        .collect(),
                })?,
                funds: vec![],
            },
            submessage_id,
        )))
    }
}

pub const REPLY_VERIFY: u64 = 1;
pub const REPLY_ROUTE: u64 = 2;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _: Env, reply: Reply) -> Result<Response, ContractError> {
    let should_route = reply.id == REPLY_ROUTE;

    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let verifier_reply: Vec<(String, bool)> = from_binary(&data)?;

            let cached_msgs = CACHED.load(deps.storage)?.messages;
            let msgs = process_verifier_response(&cached_msgs, verifier_reply)?;

            let router = CONFIG.load(deps.storage)?.router;
            Ok(Response::new()
                .set_data(to_binary(
                    &msgs
                        .iter()
                        .map(|(msg, is_verified)| (msg.id(), *is_verified))
                        .collect::<Vec<(String, bool)>>(),
                )?)
                .add_messages(if should_route {
                    make_router_messages(&msgs, router)?
                } else {
                    vec![]
                })
                .add_events(msgs.into_iter().map(|msg| make_event(msg, should_route))))
        }
        _ => Err(ContractError::Std(StdError::GenericErr {
            msg: "invalid verifier reply".to_string(),
        })),
    }
}

// Builds a vector of wasm messages to pass to the router
// only messages with an Executed status are added to the returned veector
fn make_router_messages(
    msgs: &Vec<(Message, bool)>,
    router: Addr,
) -> Result<Vec<WasmMsg>, ContractError> {
    let mut to_route = vec![];

    for (m, is_verified) in msgs {
        if *is_verified {
            to_route.push(WasmMsg::Execute {
                contract_addr: router.to_string(),
                msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessage(
                    m.clone().into(),
                ))?,
                funds: vec![],
            });
        }
    }

    Ok(to_route)
}

fn process_verifier_response(
    msgs: &[Message],
    verifier_response: Vec<(String, bool)>,
) -> Result<Vec<(Message, bool)>, ContractError> {
    verifier_response
        .into_iter()
        .map(|(id, is_verified)| -> Result<(Message, bool), _> {
            msgs.iter()
                .find(|msg| msg.id() == *id)
                .ok_or(ContractError::MessageNotFound {
                    message_id: id.clone(),
                })
                .map(|m| (m.clone(), is_verified))
        })
        .collect()
}

// Creates an appropriate event for the passed in message, depending on the verification status
// and if the message is intended for routing
fn make_event(res: (Message, bool), should_route: bool) -> Event {
    if should_route {
        return make_routing_event(res);
    }
    make_verification_event(res)
}

fn make_routing_event((msg, is_verified): (Message, bool)) -> Event {
    if !is_verified {
        return GatewayEvent::MessageRoutingFailed { msg }.into();
    }
    GatewayEvent::MessageRouted { msg }.into()
}

fn make_verification_event((msg, is_verified): (Message, bool)) -> Event {
    if !is_verified {
        return GatewayEvent::MessageVerificationFailed { msg }.into();
    }
    GatewayEvent::MessageVerified { msg }.into()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMessages { message_ids } => {
            let mut msgs = vec![];

            for id in message_ids {
                msgs.push(OUTGOING_MESSAGES.load(deps.storage, id)?);
            }

            to_binary(
                &msgs
                    .into_iter()
                    .map(|m| m.into())
                    .collect::<Vec<connection_router::msg::Message>>(),
            )
        }
    }
}
