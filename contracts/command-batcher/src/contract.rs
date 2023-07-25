#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, BlockInfo, Deps, DepsMut, Env, HexBinary, MessageInfo,
    QuerierWrapper, QueryRequest, Reply, Response, StdError, StdResult, SubMsg, WasmMsg, WasmQuery,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use std::collections::HashMap;

use axelar_wasm_std::{Participant, Snapshot};
use service_registry::msg::ActiveWorkers;

use crate::{
    encoding::{traits, Message},
    error::ContractError,
    msg::ExecuteMsg,
    msg::{GetProofResponse, InstantiateMsg, QueryMsg},
    state::{Config, COMMANDS_BATCH, CONFIG, REPLY_ID_COUNTER, REPLY_ID_TO_BATCH},
    types::CommandBatch,
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
    REPLY_ID_COUNTER.save(deps.storage, &0)?;

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
        ExecuteMsg::ConstructProof { message_ids } => {
            execute::construct_proof(deps, env, message_ids)
        }
        ExecuteMsg::KeyGen { pub_keys } => execute::key_gen(deps, env, info, pub_keys),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        env: Env,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        let query = gateway::msg::QueryMsg::GetMessages { message_ids };
        let messages: Vec<connection_router::msg::Message> =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: config.gateway.into(),
                msg: to_binary(&query)?,
            }))?;

        if messages.is_empty() {
            return Err(ContractError::NoMessagesFound {});
        }

        let messages: Vec<Message> = messages
            .into_iter()
            .map(|msg| msg.try_into())
            .collect::<Result<Vec<Message>, ContractError>>()?;

        let command_batch: CommandBatch =
            traits::CommandBatch::new(env.block.height, messages, config.destination_chain_id);

        COMMANDS_BATCH.save(deps.storage, &command_batch.id, &command_batch)?;

        let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
            key_id: config.service_name,
            msg: command_batch.msg_to_sign,
        };

        let reply_id = REPLY_ID_COUNTER.update(deps.storage, |mut reply_id| -> StdResult<_> {
            reply_id += 1;
            Ok(reply_id)
        })?;
        REPLY_ID_TO_BATCH.save(deps.storage, reply_id, &command_batch.id)?;

        Ok(Response::new().add_submessage(SubMsg::reply_on_success(
            WasmMsg::Execute {
                contract_addr: config.multisig.into(),
                msg: to_binary(&start_sig_msg)?,
                funds: vec![],
            },
            reply_id,
        )))
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
pub fn reply(deps: DepsMut, _: Env, reply: Reply) -> Result<Response, ContractError> {
    let reply_id = reply.id;

    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let command_batch_id = REPLY_ID_TO_BATCH.load(deps.storage, reply_id)?;

            COMMANDS_BATCH.update(
                deps.storage,
                &command_batch_id,
                |batch| -> Result<CommandBatch, ContractError> {
                    match batch {
                        Some(mut batch) => {
                            let session_id = from_binary(&data).map_err(|_| {
                                ContractError::InvalidContractReply {
                                    reason: "invalid multisig session ID".to_string(),
                                }
                            })?;

                            batch.multisig_session_id = Some(session_id);
                            Ok(batch)
                        }
                        None => unreachable!("violated invariant: no batch found for reply id"),
                    }
                },
            )?;

            Ok(Response::default())
        }
        Ok(MsgExecuteContractResponse { data: None }) => Err(ContractError::InvalidContractReply {
            reason: "no data".to_string(),
        }),
        Err(_) => {
            unreachable!("violated invariant: replied failed submessage with ReplyOn::Success")
        }
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

        let proof_id = HexBinary::from_hex(proof_id.as_str())?.into();

        let batch = COMMANDS_BATCH.load(deps.storage, &proof_id)?;

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
