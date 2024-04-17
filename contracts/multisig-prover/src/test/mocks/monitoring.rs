use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw_storage_plus::Map;

use monitoring::msg::QueryMsg;
use multisig::worker_set::WorkerSet;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: monitoring::msg::InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterActiveWorkerSet { next_worker_set: WorkerSet },
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::RegisterActiveWorkerSet { next_worker_set } => {
            register_active_worker_set(deps, info.sender, next_worker_set);
            Ok(Response::new())
        }
    }
}

type ProverAddress = Addr;
const ACTIVE_WORKERSET_FOR_PROVER: Map<ProverAddress, WorkerSet> =
    Map::new("active_prover_workerset");

fn register_active_worker_set(deps: DepsMut, caller_address: Addr, worker_set: WorkerSet) {
    ACTIVE_WORKERSET_FOR_PROVER
        .save(deps.storage, caller_address, &(worker_set))
        .expect("Saving Active WorkerSet with Monitoring Failed");
}

pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkerSet { .. } => todo!(),
    }
}
