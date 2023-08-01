#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, wasm_execute, Binary, BlockInfo, Deps, DepsMut, Env, HexBinary,
    MessageInfo, QuerierWrapper, QueryRequest, Reply, Response, StdError, StdResult, SubMsg,
    WasmMsg, WasmQuery,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use std::collections::HashMap;

use axelar_wasm_std::{Participant, Snapshot};
use connection_router::msg::Message;
use multisig::{msg::GetSigningSessionResponse, types::MultisigState};
use service_registry::msg::ActiveWorkers;

use crate::{
    error::ContractError,
    events::Event,
    msg::ExecuteMsg,
    msg::{GetProofResponse, InstantiateMsg, ProofStatus, QueryMsg},
    state::{
        Config, COMMANDS_BATCH, CONFIG, PROOF_BATCH_MULTISIG, REPLY_ID_COUNTER, REPLY_ID_TO_BATCH,
    },
    types::{BatchID, CommandBatch, Proof, ProofID},
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
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(deps, message_ids),
        ExecuteMsg::RotateSnapshot { pub_keys } => {
            execute::rotate_snapshot(deps, env, info, pub_keys)
        }
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;

        let query = gateway::msg::QueryMsg::GetMessages { message_ids };
        let messages: Vec<Message> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.gateway.into(),
            msg: to_binary(&query)?,
        }))?;

        if messages.is_empty() {
            return Err(ContractError::NoMessagesFound {});
        }

        let message_ids: Vec<String> = messages.iter().map(|msg| msg.id.clone()).collect();
        let batch_id = BatchID::new(&message_ids);

        let command_batch = match COMMANDS_BATCH.may_load(deps.storage, &batch_id)? {
            Some(batch) => batch,
            None => {
                let batch = CommandBatch::new(messages, config.destination_chain_id)?;

                COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;

                batch
            }
        };

        let reply_id = REPLY_ID_COUNTER.update(deps.storage, |mut reply_id| -> StdResult<_> {
            reply_id += 1;
            Ok(reply_id)
        })?;
        REPLY_ID_TO_BATCH.save(deps.storage, reply_id, &command_batch.id)?;

        let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
            key_id: config.service_name,
            msg: command_batch.msg_to_sign(),
        };

        let wasm_msg = wasm_execute(config.multisig, &start_sig_msg, vec![])?;

        Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, reply_id)))
    }

    pub fn rotate_snapshot(
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

        for participant in snapshot.participants.keys() {
            if !pub_keys.contains_key(participant) {
                return Err(ContractError::PublicKeyNotFound {
                    participant: participant.to_owned(),
                });
            }
        }

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
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    let reply_id = reply.id;

    match parse_reply_execute_data(reply) {
        Ok(MsgExecuteContractResponse { data: Some(data) }) => {
            let command_batch_id = REPLY_ID_TO_BATCH.load(deps.storage, reply_id)?;

            let session_id =
                from_binary(&data).map_err(|_| ContractError::InvalidContractReply {
                    reason: "invalid multisig session ID".to_string(),
                })?;

            let proof_id = ProofID::new(&command_batch_id, &session_id);

            PROOF_BATCH_MULTISIG.save(deps.storage, &proof_id, &(command_batch_id, session_id))?;

            Ok(Response::new().add_event(Event::ProofUnderConstruction { proof_id }.into()))
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
    use super::*;

    pub fn get_proof(deps: Deps, proof_id: String) -> StdResult<GetProofResponse> {
        let config = CONFIG.load(deps.storage)?;

        let proof_id = HexBinary::from_hex(proof_id.as_str())?.into();
        let (batch_id, session_id) = PROOF_BATCH_MULTISIG.load(deps.storage, &proof_id)?;

        let batch = COMMANDS_BATCH.load(deps.storage, &batch_id)?;

        let query_msg = multisig::msg::QueryMsg::GetSigningSession { session_id };

        let session: GetSigningSessionResponse =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: config.multisig.to_string(),
                msg: to_binary(&query_msg)?,
            }))?;

        let proof = Proof::new(session.snapshot, session.signatures, session.pub_keys)
            .map_err(|e| StdError::generic_err(e.to_string()))?;

        let status = match session.state {
            MultisigState::Pending => ProofStatus::Pending,
            MultisigState::Completed => {
                let execute_data = proof.encode_execute_data(&batch.data);

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
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Uint256, Uint64,
    };

    use super::*;

    #[test]
    fn test_instantiation() {
        let instantiator = "instantiator";
        let gateway_address = "gateway_address";
        let multisig_address = "multisig_address";
        let service_registry_address = "service_registry_address";
        let destination_chain_id = Uint256::one();
        let signing_threshold = (Uint64::from(3u64), Uint64::from(5u64));
        let service_name = "service_name";

        let mut deps = mock_dependencies();
        let info = mock_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            destination_chain_id,
            signing_threshold,
            service_name: service_name.to_string(),
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.admin, instantiator);
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.destination_chain_id, destination_chain_id);
        assert_eq!(
            config.signing_threshold,
            signing_threshold.try_into().unwrap()
        );
        assert_eq!(config.service_name, service_name);

        let reply_id_counter = REPLY_ID_COUNTER.load(deps.as_ref().storage).unwrap();
        assert_eq!(reply_id_counter, 0);
    }
}
