use connection_router::msg::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw_multi_test::{App, ContractWrapper, Executor};
use cw_storage_plus::Map;
use gateway::error::ContractError;

const MOCK_VERIFIER_MESSAGES: Map<String, bool> = Map::new("verifier_messages");

#[cw_serde]
pub enum MockVerifierExecuteMsg {
    VerifyMessages { messages: Vec<Message> },
    MessagesVerified { messages: Vec<Message> },
}

pub fn mock_verifier_execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: MockVerifierExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        MockVerifierExecuteMsg::VerifyMessages { messages } => {
            let mut res = vec![];
            for m in messages {
                let m = connection_router::state::Message::try_from(m).unwrap();
                match MOCK_VERIFIER_MESSAGES
                    .may_load(deps.storage, serde_json::to_string(&m).unwrap())?
                {
                    Some(b) => res.push((m.id, b)),
                    None => res.push((m.id, false)),
                }
            }
            Ok(Response::new().set_data(to_binary(&res)?))
        }
        MockVerifierExecuteMsg::MessagesVerified { messages } => {
            for m in messages {
                let m = connection_router::state::Message::try_from(m).unwrap();
                MOCK_VERIFIER_MESSAGES.save(
                    deps.storage,
                    serde_json::to_string(&m).unwrap(),
                    &true,
                )?;
            }
            Ok(Response::new())
        }
    }
}

#[cw_serde]
pub enum MockVerifierQueryMsg {
    IsVerified { messages: Vec<Message> },
}
pub fn mock_verifier_query(deps: Deps, _env: Env, msg: MockVerifierQueryMsg) -> StdResult<Binary> {
    let mut res = vec![];

    match msg {
        MockVerifierQueryMsg::IsVerified { messages } => {
            for m in messages {
                let m = connection_router::state::Message::try_from(m).unwrap();
                match MOCK_VERIFIER_MESSAGES
                    .may_load(deps.storage, serde_json::to_string(&m).unwrap())?
                {
                    Some(v) => res.push((m.id.to_string(), v)),
                    None => res.push((m.id.to_string(), false)),
                }
            }
        }
    }
    to_binary(&res)
}

pub fn is_verified(
    app: &mut App,
    verifier_address: Addr,
    msgs: Vec<connection_router::msg::Message>,
) -> Vec<(String, bool)> {
    app.wrap()
        .query_wasm_smart(
            verifier_address,
            &MockVerifierQueryMsg::IsVerified { messages: msgs },
        )
        .unwrap()
}

pub fn mark_messages_as_verified(
    app: &mut App,
    verifier_address: Addr,
    msgs: Vec<connection_router::msg::Message>,
) {
    app.execute_contract(
        Addr::unchecked("relayer"),
        verifier_address.clone(),
        &MockVerifierExecuteMsg::MessagesVerified { messages: msgs },
        &[],
    )
    .unwrap();
}

const MOCK_ROUTER_MESSAGES: Map<String, connection_router::state::Message> =
    Map::new("router_messages");

pub fn mock_router_execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: connection_router::msg::ExecuteMsg,
) -> Result<Response, connection_router::error::ContractError> {
    match msg {
        connection_router::msg::ExecuteMsg::RouteMessages(msgs) => {
            for msg in msgs {
                let msg = connection_router::state::Message::try_from(msg)?;
                MOCK_ROUTER_MESSAGES.save(deps.storage, msg.id.to_string(), &msg)?;
            }
        }
        _ => (),
    }
    Ok(Response::new())
}

#[cw_serde]
pub enum MockRouterQueryMsg {
    GetMessages { ids: Vec<String> },
}
pub fn mock_router_query(deps: Deps, _env: Env, msg: MockRouterQueryMsg) -> StdResult<Binary> {
    let mut msgs = vec![];

    match msg {
        MockRouterQueryMsg::GetMessages { ids } => {
            for id in ids {
                match MOCK_ROUTER_MESSAGES.may_load(deps.storage, id)? {
                    Some(m) => msgs.push(m),
                    None => (),
                }
            }
        }
    }
    to_binary(&msgs)
}

pub fn get_router_messages(
    app: &mut App,
    router_address: Addr,
    msgs: Vec<connection_router::msg::Message>,
) -> Vec<connection_router::state::Message> {
    app.wrap()
        .query_wasm_smart(
            router_address,
            &MockRouterQueryMsg::GetMessages {
                ids: msgs.iter().map(|m| m.id.to_string()).collect(),
            },
        )
        .unwrap()
}

pub fn make_mock_router(app: &mut App) -> Addr {
    let code = ContractWrapper::new(
        mock_router_execute,
        |_, _, _, _: connection_router::msg::InstantiateMsg| {
            Ok::<Response, ContractError>(Response::new())
        },
        mock_router_query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &connection_router::msg::InstantiateMsg {
                admin_address: Addr::unchecked("admin").to_string(),
                governance_address: Addr::unchecked("governance").to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    contract_address
}

pub fn make_mock_verifier(app: &mut App) -> Addr {
    let code = ContractWrapper::new(
        mock_verifier_execute,
        |_, _, _, _: aggregate_verifier::msg::InstantiateMsg| {
            Ok::<Response, ContractError>(Response::new())
        },
        mock_verifier_query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("verifier"),
            &aggregate_verifier::msg::InstantiateMsg {
                verifier_address: Addr::unchecked("doesn't matter").to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    contract_address
}
