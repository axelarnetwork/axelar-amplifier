#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdError, StdResult,
};

use crate::{
    error::ContractError,
    msg::ExecuteMsg,
    msg::{GetProofResponse, QueryMsg},
    state::{COMMANDS_BATCH, CONFIG},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(message_ids),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(_message_ids: Vec<String>) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProof { proof_id } => to_binary(&query::get_proof(deps, proof_id)?),
    }
}

pub mod query {
    use cosmwasm_std::{QueryRequest, WasmQuery};
    use multisig::{msg::GetSigningSessionResponse, types::MultisigState};

    use crate::{encoding::traits, msg::ProofStatus};

    use super::*;

    pub fn get_proof(deps: Deps, proof_id: String) -> StdResult<GetProofResponse> {
        let config = CONFIG.load(deps.storage)?;

        let proof_id = HexBinary::from_hex(proof_id.as_str())?;

        let batch = COMMANDS_BATCH.load(deps.storage, proof_id.as_slice())?;

        match batch.multisig_session_id {
            Some(session_id) => {
                let query_msg = multisig::msg::QueryMsg::GetSigningSession { session_id };

                let session: GetSigningSessionResponse =
                    deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                        contract_addr: config.multisig.to_string(),
                        msg: to_binary(&query_msg)?,
                    }))?;

                let proof =
                    traits::Proof::new(session.snapshot, session.signatures, session.pub_keys);

                let status = match session.state {
                    MultisigState::Pending => ProofStatus::Pending,
                    MultisigState::Completed => {
                        let execute_data = traits::Proof::encode_execute_data(&proof, &batch.data);

                        ProofStatus::Completed { execute_data }
                    }
                };

                Ok(GetProofResponse {
                    proof_id,
                    message_ids: batch.message_ids,
                    data: batch.data,
                    proof,
                    status,
                })
            }
            None => Err(StdError::not_found("multisig session ID")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
}
