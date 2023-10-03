use cosmwasm_std::{
    to_binary, wasm_execute, Addr, DepsMut, Env, QuerierWrapper, QueryRequest, Response, Storage,
    SubMsg, WasmQuery,
};
use multisig::key::{KeyType, PublicKey};

use axelar_wasm_std::snapshot;
use connection_router::state::{ChainName, CrossChainId, Message};
use service_registry::state::Worker;

use crate::{
    contract::START_MULTISIG_REPLY_ID,
    encoding::{make_operators, CommandBatchBuilder},
    error::ContractError,
    state::{
        Config, WorkerSet, COMMANDS_BATCH, CONFIG, CURRENT_WORKER_SET, KEY_ID, NEXT_WORKER_SET,
        REPLY_BATCH,
    },
    types::{BatchID, WorkersInfo},
};

pub fn construct_proof(
    deps: DepsMut,
    env: Env,
    message_ids: Vec<String>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let batch_id = BatchID::new(&message_ids, None);

    let messages = get_messages(
        deps.querier,
        message_ids,
        config.gateway.clone(),
        config.chain_name.clone(),
    )?;

    let command_batch = match COMMANDS_BATCH.may_load(deps.storage, &batch_id)? {
        Some(batch) => batch,
        None => {
            let workers_info = get_workers_info(&deps, &env, &config)?;
            let new_worker_set = get_next_worker_set(&deps, &env, &config)?;
            let mut builder = CommandBatchBuilder::new(config.destination_chain_id, config.encoder);

            if let Some(new_worker_set) = new_worker_set {
                save_next_worker_set(deps.storage, workers_info, new_worker_set.clone())?;
                builder.add_new_worker_set(new_worker_set)?;
            }

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

    let key_id = KEY_ID.load(deps.storage)?;
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id,
        msg: command_batch.msg_digest(),
    };

    let wasm_msg = wasm_execute(config.multisig, &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn get_messages(
    querier: QuerierWrapper,
    message_ids: Vec<String>,
    gateway: Addr,
    chain_name: ChainName,
) -> Result<Vec<Message>, ContractError> {
    let length = message_ids.len();

    let ids = message_ids
        .into_iter()
        .map(|id| {
            id.parse::<CrossChainId>()
                .expect("ids should have correct format")
        })
        .collect::<Vec<_>>();
    let query = gateway::msg::QueryMsg::GetMessages { message_ids: ids };
    let messages: Vec<Message> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: gateway.into(),
        msg: to_binary(&query)?,
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

fn get_workers_info(
    deps: &DepsMut,
    env: &Env,
    config: &Config,
) -> Result<WorkersInfo, ContractError> {
    let active_workers_query = service_registry::msg::QueryMsg::GetActiveWorkers {
        service_name: config.service_name.clone(),
        chain_name: config.chain_name.to_string(),
    };

    let workers: Vec<Worker> = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry.to_string(),
        msg: to_binary(&active_workers_query)?,
    }))?;

    let participants = workers
        .clone()
        .into_iter()
        .map(service_registry::state::Worker::try_into)
        .collect::<Result<Vec<snapshot::Participant>, _>>()?;

    let snapshot = snapshot::Snapshot::new(
        env.block.time.try_into()?,
        env.block.height.try_into()?,
        config.signing_threshold,
        participants.clone().try_into()?,
    );

    let mut pub_keys = vec![];
    for worker in &workers {
        let pub_key_query = multisig::msg::QueryMsg::GetPublicKey {
            worker_address: worker.address.to_string(),
            key_type: KeyType::Ecdsa,
        };
        let pub_key: PublicKey = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.multisig.to_string(),
            msg: to_binary(&pub_key_query)?,
        }))?;
        pub_keys.push(pub_key);
    }

    Ok(WorkersInfo {
        snapshot,
        pubkeys_by_participant: participants.into_iter().zip(pub_keys).collect(),
    })
}

fn make_worker_set(deps: &DepsMut, env: &Env, config: &Config) -> Result<WorkerSet, ContractError> {
    let workers_info = get_workers_info(deps, env, config)?;
    WorkerSet::new(
        workers_info.pubkeys_by_participant,
        workers_info.snapshot.quorum.into(),
        env.block.height,
    )
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
    workers_info: WorkersInfo,
    new_worker_set: WorkerSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, &new_worker_set) {
        return Err(ContractError::WorkerSetConfirmationInProgress);
    }

    Ok(NEXT_WORKER_SET.save(storage, &(new_worker_set, workers_info.snapshot))?)
}

fn initialize_worker_set(
    storage: &mut dyn Storage,
    new_worker_set: WorkerSet,
) -> Result<(), ContractError> {
    let key_id = new_worker_set.id(); // this is really just the worker_set_id

    CURRENT_WORKER_SET.save(storage, &new_worker_set)?;
    KEY_ID.save(storage, &key_id)?;

    Ok(())
}

fn make_keygen_msg(
    key_id: String,
    snapshot: axelar_wasm_std::Snapshot,
    worker_set: WorkerSet,
) -> multisig::msg::ExecuteMsg {
    multisig::msg::ExecuteMsg::KeyGen {
        key_id,
        snapshot,
        pub_keys_by_address: worker_set
            .signers
            .into_iter()
            .map(|signer| {
                (
                    signer.address.to_string(),
                    (KeyType::Ecdsa, signer.pub_key.as_ref().into()),
                )
            })
            .collect(),
    }
}

pub fn update_worker_set(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let workers_info = get_workers_info(&deps, &env, &config)?;
    let cur_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;

    match cur_worker_set {
        None => {
            // if no worker set, just store it and return
            let new_worker_set = make_worker_set(&deps, &env, &config)?;
            initialize_worker_set(deps.storage, new_worker_set.clone())?;
            let key_gen_msg = make_keygen_msg(
                new_worker_set.id(),
                workers_info.snapshot,
                new_worker_set.clone(),
            );

            Ok(Response::new().add_message(wasm_execute(config.multisig, &key_gen_msg, vec![])?))
        }
        Some(cur_worker_set) => {
            let new_worker_set = get_next_worker_set(&deps, &env, &config)?
                .ok_or(ContractError::WorkerSetUnchanged)?;

            save_next_worker_set(deps.storage, workers_info, new_worker_set.clone())?;

            let mut builder = CommandBatchBuilder::new(config.destination_chain_id, config.encoder);
            builder.add_new_worker_set(new_worker_set)?;

            let batch = builder.build()?;

            COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;
            REPLY_BATCH.save(deps.storage, &batch.id)?;

            let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
                key_id: cur_worker_set.id(), // TODO remove the key_id
                msg: batch.msg_digest(),
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

    let (worker_set, snapshot) = NEXT_WORKER_SET.load(deps.storage)?;

    let query = voting_verifier::msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: make_operators(worker_set.clone(), config.encoder),
    };

    let is_confirmed: bool = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.voting_verifier.to_string(),
        msg: to_binary(&query)?,
    }))?;

    if !is_confirmed {
        return Err(ContractError::WorkerSetNotConfirmed);
    }

    CURRENT_WORKER_SET.save(deps.storage, &worker_set)?;
    NEXT_WORKER_SET.remove(deps.storage);
    KEY_ID.save(deps.storage, &worker_set.id())?;

    let key_gen_msg = multisig::msg::ExecuteMsg::KeyGen {
        key_id: worker_set.id(),
        snapshot, // TODO: refactor this to just pass the WorkerSet struct
        pub_keys_by_address: worker_set
            .signers
            .into_iter()
            .map(|signer| {
                (
                    signer.address.to_string(),
                    (KeyType::Ecdsa, signer.pub_key.as_ref().into()),
                )
            })
            .collect(),
    };

    Ok(Response::new().add_message(wasm_execute(config.multisig, &key_gen_msg, vec![])?))
}

pub fn should_update_worker_set(
    new_workers: &WorkerSet,
    cur_workers: &WorkerSet,
    max_diff: usize,
) -> bool {
    new_workers.signers.difference(&cur_workers.signers).count()
        + cur_workers.signers.difference(&new_workers.signers).count()
        > max_diff
}

// Returns true if there is a different worker set pending for confirmation, false if there is no
// worker set pending or if the pending set is the same. We can't use direct comparison
// because the created_at might be different, so we compare only the signers and threshold.
fn different_set_in_progress(storage: &dyn Storage, new_worker_set: &WorkerSet) -> bool {
    if let Ok(Some((next_worker_set, _))) = NEXT_WORKER_SET.may_load(storage) {
        return next_worker_set.signers != new_worker_set.signers
            || next_worker_set.threshold != new_worker_set.threshold;
    }

    false
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::Snapshot;
    use cosmwasm_std::{testing::mock_dependencies, Timestamp, Uint256, Uint64};

    use crate::{execute::should_update_worker_set, state::NEXT_WORKER_SET, test::test_data};
    use std::collections::{BTreeSet, HashMap};

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
        signers[0].pub_key = signers[1].pub_key.clone();
        signers[1].pub_key = signers[0].pub_key.clone();
        new_worker_set.signers = BTreeSet::from_iter(signers);
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
            .save(deps.as_mut().storage, &(new_worker_set.clone(), snapshot()))
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
            .save(deps.as_mut().storage, &(new_worker_set.clone(), snapshot()))
            .unwrap();

        new_worker_set.signers.pop_first();

        assert!(different_set_in_progress(
            deps.as_ref().storage,
            &new_worker_set
        ));
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            timestamp: Timestamp::from_nanos(1).try_into().unwrap(),
            height: Uint64::one().try_into().unwrap(),
            total_weight: Uint256::one().try_into().unwrap(),
            quorum: Uint256::one().try_into().unwrap(),
            participants: HashMap::new(),
        }
    }
}
