use cosmwasm_std::{to_binary, Deps, HexBinary, QueryRequest, StdError, StdResult, WasmQuery};

use multisig::{msg::Multisig, types::MultisigState};

use crate::{
    msg::{GetProofResponse, ProofStatus},
    state::{COMMANDS_BATCH, CONFIG, PROOF_BATCH_MULTISIG},
};

pub fn get_proof(deps: Deps, proof_id: String) -> StdResult<GetProofResponse> {
    let config = CONFIG.load(deps.storage)?;

    let proof_id = HexBinary::from_hex(proof_id.as_str())?.into();
    let (batch_id, session_id) = PROOF_BATCH_MULTISIG.load(deps.storage, &proof_id)?;

    let batch = COMMANDS_BATCH.load(deps.storage, &batch_id)?;

    let query_msg = multisig::msg::QueryMsg::GetMultisig { session_id };

    let multisig: Multisig = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.multisig.to_string(),
        msg: to_binary(&query_msg)?,
    }))?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed => {
            let execute_data = batch
                .encode_execute_data(multisig.quorum, multisig.signers)
                .map_err(|e| {
                    StdError::generic_err(format!("failed to encode execute data: {}", e))
                })?;

            ProofStatus::Completed { execute_data }
        }
    };

    Ok(GetProofResponse {
        proof_id,
        message_ids: batch.message_ids,
        data: batch.data,
        status,
    })
}
