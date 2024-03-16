use std::collections::BTreeMap;

use cosmwasm_std::{
    to_json_binary, wasm_execute, Addr, DepsMut, Env, MessageInfo, QuerierWrapper, QueryRequest,
    Response, Storage, SubMsg, WasmQuery,
};

use itertools::Itertools;
use multisig::{key::PublicKey, msg::Signer, worker_set::WorkerSet};

use axelar_wasm_std::{snapshot, VerificationStatus};
use connection_router_api::{ChainName, CrossChainId, Message};
use service_registry::state::WeightedWorker;

use crate::{
    contract::START_MULTISIG_REPLY_ID,
    encoding::{make_operators, CommandBatchBuilder},
    error::ContractError,
    state::{Config, COMMANDS_BATCH, CONFIG, CURRENT_WORKER_SET, NEXT_WORKER_SET, REPLY_BATCH},
    types::{BatchId, WorkersInfo},
};

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.admin {
        admin if admin == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn construct_proof(
    deps: DepsMut,
    message_ids: Vec<CrossChainId>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let batch_id = BatchId::new(&message_ids, None);

    let messages = get_messages(
        deps.querier,
        message_ids,
        config.gateway.clone(),
        config.chain_name.clone(),
    )?;

    let command_batch = match COMMANDS_BATCH.may_load(deps.storage, &batch_id)? {
        Some(batch) => batch,
        None => {
            let mut builder = CommandBatchBuilder::new(config.destination_chain_id, config.encoder);

            for msg in messages {
                builder.add_message(msg)?;
            }
            let batch = builder.build()?;

            COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;

            batch
        }
    };

    // keep track of the batch id to use during submessage reply
    REPLY_BATCH.save(deps.storage, &command_batch.id)?;

    let worker_set_id = match CURRENT_WORKER_SET.may_load(deps.storage)? {
        Some(worker_set) => worker_set.id(),
        None => {
            return Err(ContractError::NoWorkerSet);
        }
    };
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        worker_set_id,
        msg: command_batch.msg_digest(),
        chain_name: config.chain_name,
        sig_verifier: None,
    };

    let wasm_msg = wasm_execute(config.multisig, &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn get_messages(
    querier: QuerierWrapper,
    message_ids: Vec<CrossChainId>,
    gateway: Addr,
    chain_name: ChainName,
) -> Result<Vec<Message>, ContractError> {
    let length = message_ids.len();

    let query = gateway_api::msg::QueryMsg::GetOutgoingMessages { message_ids };
    let messages: Vec<Message> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: gateway.into(),
        msg: to_json_binary(&query)?,
    }))?;

    assert!(
        messages.len() == length,
        "violated invariant: returned gateway messages count mismatch"
    );

    if messages
        .iter()
        .any(|msg| msg.destination_chain != chain_name)
    {
        panic!("violated invariant: messages from different chain found");
    }

    Ok(messages)
}

fn get_workers_info(deps: &DepsMut, config: &Config) -> Result<WorkersInfo, ContractError> {
    let active_workers_query = service_registry::msg::QueryMsg::GetActiveWorkers {
        service_name: config.service_name.clone(),
        chain_name: config.chain_name.clone(),
    };

    let workers: Vec<WeightedWorker> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.service_registry.to_string(),
            msg: to_json_binary(&active_workers_query)?,
        }))?;

    let participants = workers
        .clone()
        .into_iter()
        .map(service_registry::state::WeightedWorker::into)
        .collect::<Vec<snapshot::Participant>>();

    let snapshot =
        snapshot::Snapshot::new(config.signing_threshold, participants.clone().try_into()?);

    let mut pub_keys = vec![];
    for participant in &participants {
        let pub_key_query = multisig::msg::QueryMsg::GetPublicKey {
            worker_address: participant.address.to_string(),
            key_type: config.key_type,
        };
        let pub_key: PublicKey = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.multisig.to_string(),
            msg: to_json_binary(&pub_key_query)?,
        }))?;
        pub_keys.push(pub_key);
    }

    Ok(WorkersInfo {
        snapshot,
        pubkeys_by_participant: participants.into_iter().zip(pub_keys).collect(),
    })
}

fn make_worker_set(deps: &DepsMut, env: &Env, config: &Config) -> Result<WorkerSet, ContractError> {
    let workers_info = get_workers_info(deps, config)?;
    Ok(WorkerSet::new(
        workers_info.pubkeys_by_participant,
        workers_info.snapshot.quorum.into(),
        env.block.height,
    ))
}

fn get_next_worker_set(
    deps: &DepsMut,
    env: &Env,
    config: &Config,
) -> Result<Option<WorkerSet>, ContractError> {
    let cur_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;
    let new_worker_set = make_worker_set(deps, env, config)?;

    match cur_worker_set {
        Some(cur_worker_set) => {
            if should_update_worker_set(
                &new_worker_set,
                &cur_worker_set,
                config.worker_set_diff_threshold as usize,
            ) {
                Ok(Some(new_worker_set))
            } else {
                Ok(None)
            }
        }
        None => Err(ContractError::NoWorkerSet),
    }
}

fn save_next_worker_set(
    storage: &mut dyn Storage,
    new_worker_set: &WorkerSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_worker_set) {
        return Err(ContractError::WorkerSetConfirmationInProgress);
    }

    NEXT_WORKER_SET.save(storage, new_worker_set)?;
    Ok(())
}

pub fn update_worker_set(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let cur_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;

    match cur_worker_set {
        None => {
            // if no worker set, just store it and return
            let new_worker_set = make_worker_set(&deps, &env, &config)?;
            CURRENT_WORKER_SET.save(deps.storage, &new_worker_set)?;

            Ok(Response::new().add_message(wasm_execute(
                config.multisig,
                &multisig::msg::ExecuteMsg::RegisterWorkerSet {
                    worker_set: new_worker_set,
                },
                vec![],
            )?))
        }
        Some(cur_worker_set) => {
            let new_worker_set = get_next_worker_set(&deps, &env, &config)?
                .ok_or(ContractError::WorkerSetUnchanged)?;

            save_next_worker_set(deps.storage, &new_worker_set)?;

            let mut builder = CommandBatchBuilder::new(config.destination_chain_id, config.encoder);
            builder.add_new_worker_set(new_worker_set)?;

            let batch = builder.build()?;

            COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;
            REPLY_BATCH.save(deps.storage, &batch.id)?;

            let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
                worker_set_id: cur_worker_set.id(),
                msg: batch.msg_digest(),
                sig_verifier: None,
                chain_name: config.chain_name,
            };

            Ok(Response::new().add_submessage(SubMsg::reply_on_success(
                wasm_execute(config.multisig, &start_sig_msg, vec![])?,
                START_MULTISIG_REPLY_ID,
            )))
        }
    }
}

pub fn confirm_worker_set(deps: DepsMut) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let worker_set = NEXT_WORKER_SET.load(deps.storage)?;

    let query = voting_verifier::msg::QueryMsg::GetWorkerSetStatus {
        new_operators: make_operators(worker_set.clone(), config.encoder),
    };

    let status: VerificationStatus = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.voting_verifier.to_string(),
        msg: to_json_binary(&query)?,
    }))?;

    if status != VerificationStatus::SucceededOnChain {
        return Err(ContractError::WorkerSetNotConfirmed);
    }

    CURRENT_WORKER_SET.save(deps.storage, &worker_set)?;
    NEXT_WORKER_SET.remove(deps.storage);

    Ok(Response::new().add_message(wasm_execute(
        config.multisig,
        &multisig::msg::ExecuteMsg::RegisterWorkerSet { worker_set },
        vec![],
    )?))
}

pub fn should_update_worker_set(
    new_workers: &WorkerSet,
    cur_workers: &WorkerSet,
    max_diff: usize,
) -> bool {
    signers_symetric_difference_count(&new_workers.signers, &cur_workers.signers) > max_diff
}

fn signers_symetric_difference_count(
    s1: &BTreeMap<String, Signer>,
    s2: &BTreeMap<String, Signer>,
) -> usize {
    signers_difference_count(s1, s2).saturating_add(signers_difference_count(s2, s1))
}

fn signers_difference_count(s1: &BTreeMap<String, Signer>, s2: &BTreeMap<String, Signer>) -> usize {
    s1.values().filter(|v| !s2.values().contains(v)).count()
}

// Returns true if there is a different worker set pending for confirmation, false if there is no
// worker set pending or if the pending set is the same. We can't use direct comparison
// because the created_at might be different, so we compare only the signers and threshold.
fn different_set_in_progress(storage: &dyn Storage, new_worker_set: &WorkerSet) -> bool {
    if let Ok(Some(next_worker_set)) = NEXT_WORKER_SET.may_load(storage) {
        return next_worker_set.signers != new_worker_set.signers
            || next_worker_set.threshold != new_worker_set.threshold;
    }

    false
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use crate::{execute::should_update_worker_set, state::NEXT_WORKER_SET, test::test_data};
    use std::collections::BTreeMap;

    use super::different_set_in_progress;

    #[test]
    fn should_update_worker_set_no_change() {
        let worker_set = test_data::new_worker_set();
        assert!(!should_update_worker_set(&worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_less() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(should_update_worker_set(&new_worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more_higher_threshold() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(!should_update_worker_set(&worker_set, &new_worker_set, 1));
    }

    #[test]
    fn should_update_worker_set_diff_pub_key() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        let mut signers = new_worker_set.signers.into_iter().collect::<Vec<_>>();
        // swap public keys
        signers[0].1.pub_key = signers[1].1.pub_key.clone();
        signers[1].1.pub_key = signers[0].1.pub_key.clone();
        new_worker_set.signers = BTreeMap::from_iter(signers);
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }

    #[test]
    fn test_no_set_pending_confirmation() {
        let deps = mock_dependencies();
        let new_worker_set = test_data::new_worker_set();

        assert!(!different_set_in_progress(
            deps.as_ref().storage,
            &new_worker_set
        ));
    }

    #[test]
    fn test_same_set_pending_confirmation() {
        let mut deps = mock_dependencies();
        let mut new_worker_set = test_data::new_worker_set();

        NEXT_WORKER_SET
            .save(deps.as_mut().storage, &new_worker_set)
            .unwrap();

        new_worker_set.created_at += 1;

        assert!(!different_set_in_progress(
            deps.as_ref().storage,
            &new_worker_set
        ));
    }

    #[test]
    fn test_different_set_pending_confirmation() {
        let mut deps = mock_dependencies();
        let mut new_worker_set = test_data::new_worker_set();

        NEXT_WORKER_SET
            .save(deps.as_mut().storage, &new_worker_set)
            .unwrap();

        new_worker_set.signers.pop_first();

        assert!(different_set_in_progress(
            deps.as_ref().storage,
            &new_worker_set
        ));
    }
}
