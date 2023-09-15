use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw_multi_test::{App, Executor};
use cw_storage_plus::Map;
use service_registry::{
    msg::{InstantiateMsg, QueryMsg},
    state::{AuthorizationState, BondingState, Worker},
};

use crate::test::test_data::TestOperator;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

#[cw_serde]
pub enum ExecuteMsg {
    SetActiveWorkers { workers: Vec<TestOperator> },
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::SetActiveWorkers { workers } => {
            set_operators(deps, workers);
            Ok(Response::new())
        }
    }
}

pub fn set_active_workers(
    app: &mut App,
    service_registry_address: Addr,
    workers: Vec<TestOperator>,
) {
    app.execute_contract(
        Addr::unchecked("relayer"),
        service_registry_address.clone(),
        &ExecuteMsg::SetActiveWorkers { workers },
        &[],
    )
    .unwrap();
}

const OPERATORS: Map<Addr, TestOperator> = Map::new("operators");

fn set_operators(deps: DepsMut, operators: Vec<TestOperator>) {
    OPERATORS.clear(deps.storage);
    for op in &operators {
        OPERATORS
            .save(deps.storage, op.address.clone(), op)
            .unwrap();
    }
}

pub fn get_operators(deps: Deps) -> Vec<TestOperator> {
    OPERATORS
        .prefix_range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<Vec<(Addr, TestOperator)>, _>>()
        .unwrap()
        .into_iter()
        .map(|(_, op)| op)
        .collect()
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkers {
            service_name,
            chain_name: _,
        } => {
            let workers = get_operators(deps)
                .into_iter()
                .map(|op| Worker {
                    address: op.address,
                    bonding_state: BondingState::Bonded {
                        amount: op.weight.try_into().unwrap(),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.clone(),
                })
                .collect::<Vec<Worker>>();

            to_binary(&workers)
        }
    }
}
