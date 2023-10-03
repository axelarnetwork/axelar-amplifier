use connection_router::state::{CrossChainId, Message};
use connection_router::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw_multi_test::{App, ContractWrapper, Executor};
use cw_storage_plus::Map;

const MOCK_GATEWAY_MESSAGES: Map<CrossChainId, Message> = Map::new("gateway_messages");

#[cw_serde]
pub enum MockGatewayExecuteMsg {
    RouteMessages(Vec<Message>),
}

pub fn mock_gateway_execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: MockGatewayExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        MockGatewayExecuteMsg::RouteMessages(messages) => {
            for m in messages {
                MOCK_GATEWAY_MESSAGES.save(deps.storage, m.cc_id.clone(), &m)?;
            }
            Ok(Response::new())
        }
    }
}

#[cw_serde]
pub enum MockGatewayQueryMsg {
    GetMessages { ids: Vec<CrossChainId> },
}
pub fn mock_gateway_query(deps: Deps, _env: Env, msg: MockGatewayQueryMsg) -> StdResult<Binary> {
    let mut msgs = vec![];

    match msg {
        MockGatewayQueryMsg::GetMessages { ids } => {
            for id in ids {
                match MOCK_GATEWAY_MESSAGES.may_load(deps.storage, id)? {
                    Some(m) => msgs.push(m),
                    None => (),
                }
            }
        }
    }
    to_binary(&msgs)
}

pub fn get_gateway_messages(
    app: &mut App,
    gateway_address: Addr,
    msgs: &Vec<Message>,
) -> Vec<Message> {
    app.wrap()
        .query_wasm_smart(
            gateway_address,
            &MockGatewayQueryMsg::GetMessages {
                ids: msgs.iter().map(|msg| msg.cc_id.clone()).collect(),
            },
        )
        .unwrap()
}

pub fn make_mock_gateway(app: &mut App) -> Addr {
    let code = ContractWrapper::new(
        mock_gateway_execute,
        |_, _, _, _: connection_router::msg::InstantiateMsg| {
            Ok::<Response, ContractError>(Response::new())
        },
        mock_gateway_query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("sender"),
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
