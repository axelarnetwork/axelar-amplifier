use cosmwasm_std::{to_json_binary, Deps, QueryRequest, StdResult, Uint64, WasmQuery};
use error_stack::Result;

use multisig::{multisig::Multisig, types::MultisigState, verifier_set::VerifierSet};

use crate::{
    error::ContractError,
    msg::{GetProofResponse, ProofStatus},
    state::{CONFIG, CURRENT_VERIFIER_SET, MULTISIG_SESSION_PAYLOAD, PAYLOAD},
};

pub fn get_proof(
    deps: Deps,
    multisig_session_id: Uint64,
) -> Result<GetProofResponse, ContractError> {
    let config = CONFIG.load(deps.storage).map_err(ContractError::from)?;

    let payload_id = MULTISIG_SESSION_PAYLOAD
        .load(deps.storage, multisig_session_id.u64())
        .map_err(ContractError::from)?;

    let query_msg = multisig::msg::QueryMsg::GetMultisig {
        session_id: multisig_session_id,
    };

    let multisig: Multisig = deps
        .querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.multisig.to_string(),
            msg: to_json_binary(&query_msg).map_err(ContractError::from)?,
        }))
        .map_err(ContractError::from)?;

    let payload = PAYLOAD
        .load(deps.storage, &payload_id)
        .map_err(ContractError::from)?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let execute_data = payload.execute_data(
                config.encoder,
                &config.domain_separator,
                &multisig.verifier_set,
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

pub fn get_verifier_set(deps: Deps) -> StdResult<Option<VerifierSet>> {
    CURRENT_VERIFIER_SET.may_load(deps.storage)
}
