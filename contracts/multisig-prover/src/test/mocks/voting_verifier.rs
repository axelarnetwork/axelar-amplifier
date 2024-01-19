use axelar_wasm_std::{hash::Hash, operators::Operators, VerificationStatus};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdError,
    StdResult, Uint256,
};
use cw_multi_test::{App, Executor};
use cw_storage_plus::Map;
use voting_verifier::msg::{ExecuteMsg, QueryMsg};

#[cw_serde]
pub struct InstantiateMsg {}

use crate::test::test_data::TestOperator;

pub const CONFIRMED_WORKER_SETS: Map<&Hash, ()> = Map::new("confirmed_worker_sets");
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::VerifyWorkerSet {
            message_id: _,
            new_operators,
        } => {
            CONFIRMED_WORKER_SETS.save(deps.storage, &new_operators.hash(), &())?;
            Ok(Response::new())
        }
        _ => unimplemented!(),
    }
}

pub fn confirm_worker_set(
    app: &mut App,
    voting_verifier_address: Addr,
    workers: Vec<TestOperator>,
    threshold: Uint256,
) {
    let new_operators: Vec<(HexBinary, Uint256)> = workers
        .iter()
        .map(|worker| (worker.operator.clone(), worker.weight))
        .collect();
    app.execute_contract(
        Addr::unchecked("relayer"),
        voting_verifier_address.clone(),
        &ExecuteMsg::VerifyWorkerSet {
            message_id: "ethereum:00".parse().unwrap(),
            new_operators: Operators::new(new_operators, threshold),
        },
        &[],
    )
    .unwrap();
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetWorkerSetStatus { new_operators } => to_binary(
            &CONFIRMED_WORKER_SETS
                .may_load(deps.storage, &new_operators.hash())?
                .map_or(VerificationStatus::None, |_| {
                    VerificationStatus::SucceededOnChain
                }),
        ),
        _ => unimplemented!(),
    }
}
