#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, BlockInfo, Deps, DepsMut, Env, HexBinary, MessageInfo, QuerierWrapper,
    QueryRequest, Response, StdError, StdResult, WasmMsg, WasmQuery,
};

use std::collections::HashMap;

use axelar_wasm_std::{Participant, Snapshot};
use service_registry::msg::ActiveWorkers;

use crate::{
    error::ContractError,
    msg::ExecuteMsg,
    msg::{GetProofResponse, InstantiateMsg, QueryMsg},
    state::{Config, COMMANDS_BATCH, CONFIG},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(info.sender.as_str())?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let multisig = deps.api.addr_validate(&msg.multisig_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    let config = Config {
        admin,
        gateway,
        multisig,
        service_registry,
        destination_chain_id: msg.destination_chain_id,
        signing_threshold: msg.signing_threshold.try_into().map_err(
            |e: axelar_wasm_std::threshold::Error| ContractError::InvalidInput {
                reason: e.to_string(),
            },
        )?,
        service_name: msg.service_name,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(message_ids),
        ExecuteMsg::KeyGen { pub_keys } => execute::key_gen(deps, env, info, pub_keys),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(_message_ids: Vec<String>) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn key_gen(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        pub_keys: HashMap<String, HexBinary>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.admin != info.sender {
            return Err(ContractError::Unauthorized {});
        }

        let snapshot = snapshot(deps.querier, env.block, &config)?;

        let keygen_msg = multisig::msg::ExecuteMsg::KeyGen {
            key_id: config.service_name,
            snapshot,
            pub_keys,
        };

        Ok(Response::new().add_message(WasmMsg::Execute {
            contract_addr: config.multisig.into(),
            msg: to_binary(&keygen_msg)?,
            funds: vec![],
        }))
    }

    fn snapshot(
        querier: QuerierWrapper,
        block: BlockInfo,
        config: &Config,
    ) -> Result<Snapshot, ContractError> {
        let query_msg = service_registry::msg::QueryMsg::GetActiveWorkers {
            service_name: config.service_name.clone(),
        };

        let active_workers: ActiveWorkers =
            querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: config.service_registry.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let participants = active_workers
            .workers
            .into_iter()
            .map(service_registry::state::Worker::try_into)
            .collect::<Result<Vec<Participant>, axelar_wasm_std::nonempty::Error>>()
            .map_err(
                |err: axelar_wasm_std::nonempty::Error| ContractError::InvalidParticipants {
                    reason: err.to_string(),
                },
            )?
            .try_into()
            .map_err(|err: axelar_wasm_std::nonempty::Error| {
                ContractError::InvalidParticipants {
                    reason: err.to_string(),
                }
            })?;

        Ok(Snapshot::new(
            block
                .time
                .try_into()
                .expect("violated invariant: block time is zero"),
            block
                .height
                .try_into()
                .expect("violated invariant: block height is zero"),
            config.signing_threshold,
            participants,
        ))
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
