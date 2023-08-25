use cosmwasm_std::{
    to_binary, wasm_execute, Addr, BlockInfo, DepsMut, Env, HexBinary, QuerierWrapper,
    QueryRequest, Response, SubMsg, WasmMsg, WasmQuery,
};

use std::{collections::HashMap, str::FromStr};

use axelar_wasm_std::{Participant, Snapshot};
use connection_router::{msg::Message, types::ChainName};
use service_registry::state::Worker;

use crate::{
    contract::START_MULTISIG_REPLY_ID,
    error::ContractError,
    events::Event,
    state::{Config, COMMANDS_BATCH, CONFIG, KEY_ID, REPLY_BATCH},
    types::{BatchID, CommandBatch},
};

pub fn construct_proof(deps: DepsMut, message_ids: Vec<String>) -> Result<Response, ContractError> {
    let key_id = KEY_ID.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;

    let batch_id = BatchID::new(&message_ids);

    let messages = get_messages(deps.querier, message_ids, config.gateway, config.chain_name)?;

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
        .collect::<Result<Vec<Participant>, _>>()
        .map_err(
            |err: service_registry::ContractError| ContractError::InvalidParticipants {
                reason: err.to_string(),
            },
        )?
        .try_into()
        .map_err(
            |err: axelar_wasm_std::nonempty::Error| ContractError::InvalidParticipants {
                reason: err.to_string(),
            },
        )?;

    Ok(Snapshot::new(
        block
            .time
            .try_into()
            .expect("violated invariant: block time cannot be zero"),
        block
            .height
            .try_into()
            .expect("violated invariant: block height cannot be zero"),
        config.signing_threshold,
        participants,
    ))
}
