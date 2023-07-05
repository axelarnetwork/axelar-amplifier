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
    env: Env,
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
                route_incoming_messages(env, deps, msgs)
            }
        }
    }
}

pub mod execute {

    use cosmwasm_std::{to_binary, Addr, QueryRequest, SubMsg, WasmMsg, WasmQuery};

    use crate::{
        events::GatewayEvent,
        state::{CallbackCache, CACHED, OUTGOING_MESSAGES},
    };

    use super::*;

    pub fn verify_messages(
        deps: DepsMut,
        mut msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let verifier = config.verifier;

        let orig_len = msgs.len();
        msgs.sort_unstable_by_key(|a| a.id());
        msgs.dedup_by(|a, b| a.id() == b.id());
        if msgs.len() != orig_len {
            return Err(ContractError::DuplicateMessageID {});
        }

        Ok(Response::new().add_message(WasmMsg::Execute {
            contract_addr: verifier.to_string(),
            msg: to_binary(&aggregate_verifier::msg::ExecuteMsg::VerifyMessages {
                messages: msgs
                    .into_iter()
                    .map(connection_router::msg::Message::from)
                    .collect(),
            })?,
            funds: vec![],
        }))
    }

    pub fn route_incoming_messages(
        env: Env,
        deps: DepsMut,
        mut msgs: Vec<Message>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let verifier = config.verifier;
        let orig_len = msgs.len();
        msgs.sort_unstable_by_key(|a| a.id());
        msgs.dedup_by(|a, b| a.id() == b.id());
        if msgs.len() != orig_len {
            return Err(ContractError::DuplicateMessageID {});
        }
        let query_msg = aggregate_verifier::msg::QueryMsg::IsVerified {
            messages: msgs.iter().map(|m| m.clone().into()).collect(),
        };
        let query_response: Vec<(String, bool)> =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: verifier.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let (verified, unverified): (Vec<Message>, Vec<Message>) =
            msgs.into_iter().partition(|m| -> bool {
                match query_response.iter().find(|r| m.id() == r.0) {
                    Some((m, v)) => *v,
                    None => false,
                }
            });

        Ok(Response::new()
            .add_message(WasmMsg::Execute {
                contract_addr: verifier.to_string(),
                msg: to_binary(&connection_router::msg::ExecuteMsg::RouteMessages(
                    verified.clone()
                        .into_iter()
                        .map(connection_router::msg::Message::from)
                        .collect(),
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
