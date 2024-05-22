use cosmwasm_std::{to_json_binary, Deps, QueryRequest, StdResult, Uint64, WasmQuery};

use multisig::{multisig::Multisig, types::MultisigState, worker_set::WorkerSet};

use crate::{
    error::ContractError,
    msg::{GetProofResponse, ProofStatus},
    state::{CONFIG, CURRENT_WORKER_SET, MULTISIG_SESSION_BATCH, PAYLOAD},
};

pub fn get_proof(
    deps: Deps,
    multisig_session_id: Uint64,
) -> Result<GetProofResponse, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let payload_id = MULTISIG_SESSION_BATCH.load(deps.storage, multisig_session_id.u64())?;

    let query_msg = multisig::msg::QueryMsg::GetMultisig {
        session_id: multisig_session_id,
    };

    let multisig: Multisig = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.multisig.to_string(),
        msg: to_json_binary(&query_msg)?,
    }))?;

    let payload = PAYLOAD.load(deps.storage, &payload_id)?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let execute_data = payload.execute_data(
                config.encoder,
                &config.domain_separator,
                &multisig.worker_set,
                multisig.optimize_signatures(),
                &payload,
            )?;
            ProofStatus::Completed { execute_data }
        }
    };

    Ok(GetProofResponse {
        multisig_session_id,
        message_ids: payload.message_ids().unwrap_or_default(),
        payload,
        status,
    })
}

pub fn get_worker_set(deps: Deps) -> StdResult<WorkerSet> {
    CURRENT_WORKER_SET.load(deps.storage)
}
