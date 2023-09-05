use cosmwasm_std::{
    to_binary, wasm_execute, Addr, DepsMut, Env, QuerierWrapper, QueryRequest, Response, SubMsg,
    WasmQuery,
};
use multisig::key::{KeyType, PublicKey};

use std::str::FromStr;

use axelar_wasm_std::{snapshot, Participant, Snapshot};
use connection_router::{msg::Message, types::ChainName};
use service_registry::state::Worker;

use crate::{
    contract::START_MULTISIG_REPLY_ID,
    encoding::evm::CommandBatchBuilder,
    error::ContractError,
    state::{
        WorkerSet, COMMANDS_BATCH, CONFIG, CURRENT_WORKER_SET, KEY_ID, NEXT_WORKER_SET, REPLY_BATCH,
    },
    types::BatchID,
};

pub fn construct_proof(deps: DepsMut, message_ids: Vec<String>) -> Result<Response, ContractError> {
    let key_id = KEY_ID.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;

    let batch_id = BatchID::new(&message_ids, None);

    let messages = get_messages(deps.querier, message_ids, config.gateway, config.chain_name)?;

    let command_batch = match COMMANDS_BATCH.may_load(deps.storage, &batch_id)? {
        Some(batch) => batch,
        None => {
            let mut builder = CommandBatchBuilder::new(config.destination_chain_id);
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

    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id,
        msg: command_batch.msg_to_sign(),
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

    let query = gateway::msg::QueryMsg::GetMessages { message_ids };
    let messages: Vec<Message> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: gateway.into(),
        msg: to_binary(&query)?,
    }))?;

    assert!(
        messages.len() == length,
        "violated invariant: returned gateway messages count mismatch"
    );

    if messages.iter().any(|msg| {
        ChainName::from_str(&msg.destination_chain)
            .expect("violated invariant: message with invalid chain found")
            != chain_name
    }) {
        panic!("violated invariant: messages from different chain found");
    }

    Ok(messages)
}

fn get_workers_info(
    deps: &DepsMut,
    env: &Env,
) -> Result<(Snapshot, Vec<(Participant, PublicKey)>), ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let active_workers_query = service_registry::msg::QueryMsg::GetActiveWorkers {
        service_name: config.service_name,
        chain_name: config.chain_name.into(),
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

    Ok((snapshot, participants.into_iter().zip(pub_keys).collect()))
}

pub fn update_worker_set(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let (snapshot, participants) = get_workers_info(&deps, &env)?;


    let new_worker_set = WorkerSet::new(snapshot, pub_keys, env.block.height)?;

    let cur_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;

    let key_id = new_worker_set.id();

    // if no worker set, just store it and return
    if cur_worker_set.is_none() {
        CURRENT_WORKER_SET.save(deps.storage, &new_worker_set)?;

        KEY_ID.save(deps.storage, &key_id)?;

        let key_gen_msg = multisig::msg::ExecuteMsg::KeyGen {
            key_id,
            snapshot,
            pub_keys: participants
                .into_iter()
                .map(|(participant, pub_key)| {
                    (
                        participant.address.to_string(),
                        (KeyType::ECDSA, <&[u8]>::from(&pub_key).into()),
                    )
                })
                .collect(),
        };

        return Ok(Response::new().add_message(wasm_execute(
            config.multisig,
            &key_gen_msg,
            vec![],
        )?));
    }

    if !should_update_worker_set(
        &new_worker_set,
        &cur_worker_set.clone().unwrap(),
        config.worker_set_diff_threshold as usize,
    ) {
        return Err(ContractError::WorkerSetUnchanged);
    }

    NEXT_WORKER_SET.save(deps.storage, &(new_worker_set.clone(), snapshot))?;
    let mut builder = CommandBatchBuilder::new(config.destination_chain_id);
    builder.add_new_worker_set(new_worker_set)?;

    let batch = builder.build()?;

    COMMANDS_BATCH.save(deps.storage, &batch.id, &batch)?;
    REPLY_BATCH.save(deps.storage, &batch.id)?;

    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id: cur_worker_set.unwrap().id(), // TODO remove the key_id
        msg: batch.msg_to_sign(),
    };

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(
        wasm_execute(config.multisig, &start_sig_msg, vec![])?,
        START_MULTISIG_REPLY_ID,
    )))
}

pub fn confirm_worker_set(deps: DepsMut) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let (worker_set, snapshot) = NEXT_WORKER_SET.load(deps.storage)?;

    let query = voting_verifier::msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: worker_set.clone().try_into()?,
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
    KEY_ID.save(deps.storage, &worker_set.hash().to_hex())?;

    let key_gen_msg = multisig::msg::ExecuteMsg::KeyGen {
        key_id: worker_set.id(), // TODO: replace key id with worker set id
        snapshot,                // TODO: refactor this to just pass the WorkerSet struct
        pub_keys: worker_set
            .signers
            .into_iter()
            .map(|s| {
                (
                    s.address.to_string(),
                    (KeyType::ECDSA, <&[u8]>::from(&s.pub_key).into()),
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

#[cfg(test)]
mod tests {
    use crate::{execute::should_update_worker_set, test::test_data};

    #[test]
    fn should_update_worker_set_no_change() {
        let worker_set = test_data::new_worker_set();
        assert!(!should_update_worker_set(&worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop();
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_less() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop();
        assert!(should_update_worker_set(&new_worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more_higher_threshold() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop();
        assert!(!should_update_worker_set(&worker_set, &new_worker_set, 1));
    }

    #[test]
    fn should_update_worker_set_diff_pub_key() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers[0].pub_key = worker_set.signers[1].pub_key.clone();
        new_worker_set.signers[1].pub_key = worker_set.signers[0].pub_key.clone();
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }
}
