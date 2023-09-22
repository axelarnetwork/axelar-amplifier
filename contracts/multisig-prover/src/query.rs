use cosmwasm_std::{to_binary, Deps, QueryRequest, StdError, StdResult, Uint64, WasmQuery};

use multisig::{msg::Multisig, types::MultisigState};

use crate::{
    msg::{GetProofResponse, ProofStatus},
    state::{WorkerSet, COMMANDS_BATCH, CONFIG, CURRENT_WORKER_SET, MULTISIG_SESSION_BATCH},
};

pub fn get_proof(deps: Deps, multisig_session_id: Uint64) -> StdResult<GetProofResponse> {
    let config = CONFIG.load(deps.storage)?;

    let batch_id = MULTISIG_SESSION_BATCH.load(deps.storage, multisig_session_id.u64())?;

    let batch = COMMANDS_BATCH.load(deps.storage, &batch_id)?;
    assert_eq!(batch.encoder, config.encoder);

    let query_msg = multisig::msg::QueryMsg::GetMultisig {
        session_id: multisig_session_id,
    };

    let multisig: Multisig = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.multisig.to_string(),
        msg: to_binary(&query_msg)?,
    }))?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed => {
            let execute_data = batch
                .encode_execute_data(multisig.quorum, multisig.signers)
                .map_err(|err| {
                    StdError::generic_err(format!("failed to encode execute data: {}", err))
                })?;

            ProofStatus::Completed { execute_data }
        }
    };

    Ok(GetProofResponse {
        multisig_session_id,
        message_ids: batch.message_ids,
        data: batch.data,
        status,
    })
}

pub fn get_worker_set(deps: Deps) -> StdResult<WorkerSet> {
    CURRENT_WORKER_SET.load(deps.storage)
}
