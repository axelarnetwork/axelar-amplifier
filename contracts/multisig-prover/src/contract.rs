#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, wasm_execute, Binary, BlockInfo, Deps, DepsMut, Env, HexBinary,
    MessageInfo, QuerierWrapper, QueryRequest, Reply, Response, StdError, StdResult, SubMsg,
    WasmMsg, WasmQuery,
};
use cw_utils::{parse_reply_execute_data, MsgExecuteContractResponse};

use std::{collections::HashMap, str::FromStr};

use axelar_wasm_std::{Participant, Snapshot};
use connection_router::{msg::Message, types::ChainName};
use multisig::{msg::Multisig, types::MultisigState};
use service_registry::state::Worker;

use crate::{
    error::ContractError,
    events::Event,
    msg::ExecuteMsg,
    msg::{GetProofResponse, InstantiateMsg, ProofStatus, QueryMsg},
    state::{Config, COMMANDS_BATCH, CONFIG, KEY_ID, PROOF_BATCH_MULTISIG, REPLY_BATCH},
    types::{BatchID, CommandBatch, ProofID},
};

const START_MULTISIG_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let multisig = deps.api.addr_validate(&msg.multisig_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    let config = Config {
        admin,
        gateway,
        multisig,
        service_registry,
        destination_chain_id: msg.destination_chain_id,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: ChainName::from_str(&msg.chain_name)
            .map_err(|_| ContractError::InvalidChainName {})?,
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
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(deps, message_ids),
        ExecuteMsg::RotateSnapshot { pub_keys, key_id } => {
            let config = CONFIG.load(deps.storage)?;
            if config.admin != info.sender {
                return Err(ContractError::Unauthorized {});
            }

            execute::rotate_snapshot(deps, env, config, pub_keys, key_id)
        }
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(
        deps: DepsMut,
        message_ids: Vec<String>,
    ) -> Result<Response, ContractError> {
        let key_id = KEY_ID.load(deps.storage)?;

        let config = CONFIG.load(deps.storage)?;

        let batch_id = BatchID::new(&message_ids);

        let query = gateway::msg::QueryMsg::GetMessages { message_ids };
        let messages: Vec<Message> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.gateway.into(),
            msg: to_binary(&query)?,
        }))?;

        if messages.is_empty() {
            return Err(ContractError::NoMessagesFound {});
        }

        let chain_name: String = config.chain_name.into();
        if messages
            .iter()
            .any(|msg| !msg.destination_chain.eq_ignore_ascii_case(&chain_name))
        {
            return Err(ContractError::WrongChain {});
        }

        let command_batch = match COMMANDS_BATCH.may_load(deps.storage, &batch_id)? {
            Some(batch) => batch,
            None => {
                let batch = CommandBatch::new(messages, config.destination_chain_id)?;

                COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;

                batch
            }
        };

        // keep track of the batch id to use during submessage reply
        REPLY_BATCH.save(deps.storage, &command_batch.id)?;

        let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
            key_id,
            msg: command_batch.msg_to_sign(),
        };

        let wasm_msg = wasm_execute(config.multisig, &start_sig_msg, vec![])?;

        Ok(Response::new()
            .add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
    }

    pub fn rotate_snapshot(
        deps: DepsMut,
        env: Env,
        config: Config,
        pub_keys: HashMap<String, HexBinary>,
        key_id: String,
    ) -> Result<Response, ContractError> {
        KEY_ID.save(deps.storage, &key_id)?;

        let snapshot = snapshot(deps.querier, env.block, &config)?;

        let keygen_msg = WasmMsg::Execute {
            contract_addr: config.multisig.into(),
            msg: to_binary(&multisig::msg::ExecuteMsg::KeyGen {
                key_id: key_id.clone(),
                snapshot: snapshot.clone(),
                pub_keys: pub_keys.clone(),
            })?,
            funds: vec![],
        };

        let event = Event::SnapshotRotated {
            key_id,
            snapshot,
            pub_keys,
        };

        Ok(Response::new()
            .add_message(keygen_msg)
            .add_event(event.into()))
    }

    fn snapshot(
        querier: QuerierWrapper,
        block: BlockInfo,
        config: &Config,
    ) -> Result<Snapshot, ContractError> {
        let query_msg = service_registry::msg::QueryMsg::GetActiveWorkers {
            service_name: config.service_name.clone(),
            chain_name: config.chain_name.to_string(),
        };

        let active_workers: Vec<Worker> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.service_registry.to_string(),
            msg: to_binary(&query_msg)?,
        }))?;

        let participants = active_workers
            .into_iter()
            .map(Worker::try_into)
            .collect::<Result<Vec<Participant>, service_registry::ContractError>>()
            .map_err(
                |err: service_registry::ContractError| ContractError::InvalidParticipants {
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
                .expect("violated invariant: block time cannot be invalid"),
            block
                .height
                .try_into()
                .expect("violated invariant: block height cannot be invalid"),
            config.signing_threshold,
            participants,
        ))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
}

pub mod reply {
    use super::*;

    pub fn start_multisig_reply(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
        match parse_reply_execute_data(reply) {
            Ok(MsgExecuteContractResponse { data: Some(data) }) => {
                let command_batch_id = REPLY_BATCH.load(deps.storage)?;

                let session_id =
                    from_binary(&data).map_err(|_| ContractError::InvalidContractReply {
                        reason: "invalid multisig session ID".to_string(),
                    })?;

                let proof_id = ProofID::new(&command_batch_id, &session_id);

                PROOF_BATCH_MULTISIG.save(
                    deps.storage,
                    &proof_id,
                    &(command_batch_id, session_id),
                )?;

                Ok(Response::new().add_event(Event::ProofUnderConstruction { proof_id }.into()))
            }
            Ok(MsgExecuteContractResponse { data: None }) => {
                Err(ContractError::InvalidContractReply {
                    reason: "no data".to_string(),
                })
            }
            Err(_) => {
                unreachable!("violated invariant: replied failed submessage with ReplyOn::Success")
            }
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
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, Fraction, Uint256,
    };
    use cw_multi_test::{AppResponse, Executor};
    use ethabi::{ParamType, Token};

    use crate::test::{
        multicontract::{setup_test_case, TestCaseConfig},
        test_data,
    };

    use super::*;

    const RELAYER: &str = "relayer";
    const PROOF_ID: &str = "cee4e2f00382604c3c4d5639d8f61e27d5fb39a1fa6b99cfec72493f5f679b58";

    fn execute_key_gen(
        test_case: &mut TestCaseConfig,
        pub_keys: Option<HashMap<String, HexBinary>>,
        key_id: Option<String>,
    ) -> Result<AppResponse, Error> {
        let pub_keys = match pub_keys {
            Some(keys) => keys,
            None => test_data::operators()
                .into_iter()
                .map(|op| (op.address.to_string(), op.pub_key.into()))
                .collect::<HashMap<String, HexBinary>>(),
        };

        let key_id = match key_id {
            Some(id) => id,
            None => "key_id".to_string(),
        };

        let msg = ExecuteMsg::RotateSnapshot { pub_keys, key_id };
        test_case.app.execute_contract(
            test_case.admin.clone(),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn execute_construct_proof(
        test_case: &mut TestCaseConfig,
        message_ids: Option<Vec<String>>,
    ) -> Result<AppResponse, Error> {
        let message_ids = match message_ids {
            Some(ids) => ids,
            None => test_data::messages()
                .into_iter()
                .map(|msg| msg.id.to_string())
                .collect::<Vec<String>>(),
        };

        let msg = ExecuteMsg::ConstructProof { message_ids };
        test_case.app.execute_contract(
            Addr::unchecked(RELAYER),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn query_get_proof(
        test_case: &mut TestCaseConfig,
        proof_id: Option<String>,
    ) -> StdResult<GetProofResponse> {
        let proof_id = match proof_id {
            Some(id) => id,
            None => PROOF_ID.to_string(),
        };

        test_case.app.wrap().query_wasm_smart(
            test_case.prover_address.clone(),
            &QueryMsg::GetProof { proof_id },
        )
    }

    #[test]
    fn test_instantiation() {
        let instantiator = "instantiator";
        let admin = "admin";
        let gateway_address = "gateway_address";
        let multisig_address = "multisig_address";
        let service_registry_address = "service_registry_address";
        let destination_chain_id = Uint256::one();
        let signing_threshold = (
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        )
            .try_into()
            .unwrap();
        let service_name = "service_name";

        let mut deps = mock_dependencies();
        let info = mock_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            admin_address: admin.to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            destination_chain_id,
            signing_threshold,
            service_name: service_name.to_string(),
            chain_name: "Ethereum".to_string(),
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.admin, admin);
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.destination_chain_id, destination_chain_id);
        assert_eq!(
            config.signing_threshold,
            signing_threshold.try_into().unwrap()
        );
        assert_eq!(config.service_name, service_name);
    }

    #[test]
    fn test_key_gen() {
        let mut test_case = setup_test_case();
        let res = execute_key_gen(&mut test_case, None, None);

        assert!(res.is_ok());
    }

    #[test]
    fn test_construct_proof() {
        let mut test_case = setup_test_case();
        execute_key_gen(&mut test_case, None, None).unwrap();

        let res = execute_construct_proof(&mut test_case, None).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "wasm-proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_query_proof() {
        let mut test_case = setup_test_case();
        execute_key_gen(&mut test_case, None, None).unwrap();
        execute_construct_proof(&mut test_case, None).unwrap();

        let res = query_get_proof(&mut test_case, None).unwrap();

        assert_eq!(res.proof_id.to_string(), PROOF_ID);
        assert_eq!(res.message_ids.len(), 2);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                let tokens =
                    ethabi::decode(&[ParamType::Bytes], &execute_data.as_slice()[4..]).unwrap();

                let input = match tokens[0].clone() {
                    Token::Bytes(input) => input,
                    _ => panic!("Invalid proof"),
                };

                let tokens =
                    ethabi::decode(&[ParamType::Bytes, ParamType::Bytes], input.as_slice())
                        .unwrap();

                assert_eq!(
                    tokens,
                    vec![
                        Token::Bytes(res.data.encode().to_vec()),
                        Token::Bytes(test_data::encoded_proof().to_vec())
                    ]
                );
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }
}
