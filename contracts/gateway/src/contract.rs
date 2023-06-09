#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, Event, MessageInfo, Reply, Response,
    StdError, StdResult, WasmMsg,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};
use sha256::digest;

use crate::{
    error::ContractError,
    events::GatewayEvent,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{messages, Config, MessageStatus, CACHED, CONFIG},
};

use connection_router::state::Message;

use self::execute::{execute_messages, send_messages, verify_messages};

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
        ExecuteMsg::VerifyMessages { messages } => {
            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;
            verify_messages(deps, msgs)
        }

        ExecuteMsg::ExecuteMessages { messages } => {
            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;
            execute_messages(deps, msgs)
        }

        ExecuteMsg::SendMessages { messages } => {
            let router = CONFIG.load(deps.storage)?.router;
            if info.sender != router {
                return Err(ContractError::SenderNotRouter {});
            }

            let msgs = messages
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<Vec<Message>, _>>()?;
            send_messages(deps, msgs)
        }
    }
}

pub mod execute {

    use std::collections::HashMap;

    use cosmwasm_std::{to_binary, Addr, SubMsg, WasmMsg};
    use sha256::digest;

    use crate::{
        events::GatewayEvent,
        state::{messages, CallbackCache, MessageStatus, CACHED},
    };

    use super::*;

    pub fn verify_messages(
        mut deps: DepsMut,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let verifier = CONFIG.load(deps.storage)?.verifier;

        let msgs = process_messages(
            &mut deps,
            msgs,
            |msg| -> Result<(Message, MessageStatus), ContractError> {
                Ok(msg) // Don't change message status if already set
            },
        )?;

        if needs_verification(&msgs) {
            build_response_with_submessage(deps, msgs, verifier, REPLY_VERIFY)
        } else {
            build_response(&msgs, |msg| GatewayEvent::MessageVerified { msg })
        }
    }

    pub fn execute_messages(
        mut deps: DepsMut,
        msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let verifier = config.verifier;
        let router = config.router;

        let msgs = process_messages(
            &mut deps,
            msgs,
            |msg| -> Result<(Message, MessageStatus), ContractError> {
                match msg {
                    (m, MessageStatus::Verified) => Ok((m, MessageStatus::Executed)),
                    (m, MessageStatus::Executed) => {
                        Err(ContractError::MessageAlreadyExecuted { message_id: m.id() })
                    }
                    _ => Ok(msg),
                }
            },
        )?;

        if needs_verification(&msgs) {
            build_response_with_submessage(deps, msgs, verifier, REPLY_EXECUTE)
        } else {
            Ok(
                build_response(&msgs, |msg| GatewayEvent::MessageExecuted { msg })?
                    .add_messages(make_router_messages(&msgs, router)?),
            )
        }
    }

    pub fn send_messages(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
        for m in &msgs {
            messages().save(
                deps.storage,
                digest(m.clone()),
                &(m.clone(), MessageStatus::Sent),
            )?;
        }

        Ok(Response::new().add_events(
            msgs.into_iter()
                .map(|m| GatewayEvent::MessageSent { msg: m }.into()),
        ))
    }

    // *** Helper functions ***

    // builds the response, adding the data to return and appropriate events
    // should be called when there is no need for a submessage
    fn build_response(
        msgs: &[(Message, MessageStatus)],
        make_event: fn(Message) -> GatewayEvent,
    ) -> Result<Response, ContractError> {
        Ok(Response::new()
            .set_data(to_binary(
                &msgs
                    .iter()
                    .map(|(m, s)| (m.id(), s.clone()))
                    .collect::<Vec<(String, MessageStatus)>>(),
            )?)
            .add_events(msgs.iter().map(|(m, _)| make_event(m.clone()).into())))
    }

    // builds the response, adding the appropriate submessages
    // stores the data that is needed for processing the submessage reply
    fn build_response_with_submessage(
        deps: DepsMut,
        msgs: Vec<(Message, MessageStatus)>,
        verifier: Addr,
        submessage_id: u64,
    ) -> Result<Response, ContractError> {
        CACHED.save(
            deps.storage,
            &CallbackCache {
                messages: msgs.clone(),
            },
        )?;

        let to_verify = msgs
            .into_iter()
            .filter(|(_, s)| *s == MessageStatus::Received)
            .map(|(m, _)| m);

        Ok(Response::new().add_submessage(SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: verifier.to_string(),
                msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
                    messages: to_verify
                        .into_iter()
                        .map(connection_router::msg::Message::from)
                        .collect(),
                })?,
                funds: vec![],
            },
            submessage_id,
        )))
    }

    // function to apply to transition message status
    // Can error if state transition is invalid (i.e. message was already executed)
    type MsgStateTransition =
        fn((Message, MessageStatus)) -> Result<(Message, MessageStatus), ContractError>;
    // For each message, updates the status based on state_transition function
    // Returns a vector of messages with their latest status
    // Order is not preserved
    fn process_messages(
        deps: &mut DepsMut,
        msgs: Vec<Message>,
        state_transition: MsgStateTransition,
    ) -> Result<Vec<(Message, MessageStatus)>, ContractError> {
        let mut msgs_with_status = HashMap::new();

        for m in &msgs {
            let (_, status) = messages().update(
                deps.storage,
                digest(m.clone()),
                |msg| -> Result<(Message, MessageStatus), ContractError> {
                    match msg {
                        Some(msg) => state_transition(msg),
                        None => Ok((m.clone(), MessageStatus::Received)),
                    }
                },
            )?;

            // batch should not contain duplicate message IDs
            if msgs_with_status
                .insert(m.id(), (m.clone(), status))
                .is_some()
            {
                return Err(ContractError::DuplicateMessageID {});
            }
        }

        Ok(msgs_with_status.into_values().collect())
    }

    // returns true if any msg in the argument still needs to be verified
    fn needs_verification(msgs: &[(Message, MessageStatus)]) -> bool {
        msgs.iter()
            .filter(|(_, s)| *s == MessageStatus::Received)
            .count()
            > 0
    }
}

pub const REPLY_VERIFY: u64 = 1;
pub const REPLY_EXECUTE: u64 = 2;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(mut deps: DepsMut, _: Env, reply: Reply) -> Result<Response, ContractError> {
    let should_execute = reply.id == REPLY_EXECUTE;

    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let verifier_reply: Vec<(String, bool)> = from_binary(&data)?;

            let cached_msgs = CACHED.load(deps.storage)?.messages;
            let msgs =
                process_verifier_response(&mut deps, cached_msgs, verifier_reply, should_execute)?;

            let router = CONFIG.load(deps.storage)?.router;
            Ok(Response::new()
                .set_data(to_binary(
                    &msgs
                        .iter()
                        .map(|(m, s)| (m.id(), s.clone()))
                        .collect::<Vec<(String, MessageStatus)>>(),
                )?)
                .add_messages(make_router_messages(&msgs, router)?)
                .add_events(msgs.into_iter().map(|msg| make_event(msg, should_execute))))
        }
        _ => Err(ContractError::Std(StdError::GenericErr {
            msg: "invalid verifier reply".to_string(),
        })),
    }
}

// Builds a vector of wasm messages to pass to the router
// only messages with an Executed status are added to the returned veector
fn make_router_messages(
    msgs: &Vec<(Message, MessageStatus)>,
    router: Addr,
) -> Result<Vec<WasmMsg>, ContractError> {
    let mut to_route = vec![];

    for (m, s) in msgs {
        if *s == MessageStatus::Executed {
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

// Updates each messages status based on the verifier response. Stores the new status in storage,
// and returns the new status for each message
fn process_verifier_response(
    deps: &mut DepsMut,
    mut msgs: Vec<(Message, MessageStatus)>,
    verifier_response: Vec<(String, bool)>,
    should_execute: bool, // true if ExecuteMessages was called
) -> Result<Vec<(Message, MessageStatus)>, ContractError> {
    for (id, is_verified) in &verifier_response {
        let (msg, status) = msgs.iter_mut().find(|(msg, _)| msg.id() == *id).ok_or(
            ContractError::MessageNotFound {
                message_id: id.clone(),
            },
        )?;

        *status = if !*is_verified {
            MessageStatus::Received
        } else if should_execute {
            MessageStatus::Executed
        } else {
            MessageStatus::Verified
        };

        messages().save(
            deps.storage,
            digest(msg.clone()),
            &(msg.clone(), status.clone()),
        )?;
    }

    Ok(msgs)
}

// Creates an appropriate event for the passed in message, depending on the new status,
// and if the messages should be executed or just verified
fn make_event((msg, status): (Message, MessageStatus), should_execute: bool) -> Event {
    match status {
        MessageStatus::Executed => GatewayEvent::MessageExecuted { msg }.into(),
        MessageStatus::Verified => GatewayEvent::MessageVerified { msg }.into(),
        MessageStatus::Received => {
            if should_execute {
                GatewayEvent::MessageExecutionFailed { msg }.into()
            } else {
                GatewayEvent::MessageVerificationFailed { msg }.into()
            }
        }
        MessageStatus::Sent => panic!("sent messages should never be present in reply"),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMessages { message_ids } => {
            let mut msgs = vec![];

            for id in message_ids {
                msgs.append(&mut messages().idx.id.find_messages(&deps, &id)?);
            }

            to_binary(
                &msgs
                    .into_iter()
                    .map(|(m, s)| (m.into(), s))
                    .collect::<Vec<(connection_router::msg::Message, MessageStatus)>>(),
            )
        }
    }
}
