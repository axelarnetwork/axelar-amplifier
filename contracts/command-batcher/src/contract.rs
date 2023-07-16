use axelar_wasm_std::{nonempty, Participant, Snapshot, Threshold};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, QuerierWrapper, QueryRequest,
    Response, StdResult, Uint256, WasmMsg, WasmQuery,
};
use service_registry::msg::ActiveWorkers;

use crate::{
    batch::CommandBatch,
    error::ContractError,
    msg::{ExecuteMsg, GetProofResponse, InstantiateMsg, QueryMsg},
    state::{Config, COMMANDS_BATCH, CONFIG},
    types::Message,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let multisig = deps.api.addr_validate(&msg.multisig_address)?;
    let registry = deps.api.addr_validate(&msg.registry_address)?;

    let config = Config {
        gateway,
        multisig,
        registry,
        destination_chain_id: msg.destination_chain_id,
        service_name: msg.service_name,
    };

    CONFIG.save(deps.storage, &config)?;

    let quorum_threshold: Threshold =
        msg.quorum_threshold
            .try_into()
            .map_err(
                |err: axelar_wasm_std::threshold::Error| ContractError::InvalidInput {
                    reason: err.to_string(),
                },
            )?;

    let snapshot = snapshot(deps.querier, env, config, quorum_threshold)?;

    let keygen_msg = multisig::msg::ExecuteMsg::KeyGen {
        snapshot,
        pub_keys: msg.pub_keys,
    };

    Ok(Response::new().add_message(WasmMsg::Execute {
        contract_addr: msg.multisig_address,
        msg: to_binary(&keygen_msg)?,
        funds: vec![],
    }))
}

fn snapshot(
    querier: QuerierWrapper,
    env: Env,
    config: Config,
    quorum_threshold: Threshold,
) -> Result<Snapshot, ContractError> {
    let query_msg = service_registry::msg::QueryMsg::GetActiveWorkers {
        service_name: config.service_name,
    };

    let active_workers: ActiveWorkers = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.registry.to_string(),
        msg: to_binary(&query_msg)?,
    }))?;

    let participants: nonempty::Vec<Participant> = active_workers
        .workers
        .into_iter()
        .map(|worker| Participant {
            address: worker.address,
            weight: Uint256::one()
                .try_into()
                .expect("violated invariant: non-zero type fails with non-zero value"),
        })
        .collect::<Vec<Participant>>()
        .try_into()
        .map_err(
            |err: axelar_wasm_std::nonempty::Error| ContractError::InvalidParticipants {
                reason: err.to_string(),
            },
        )?;

    Ok(Snapshot::new(
        env.block
            .time
            .try_into()
            .expect("violated invariant: block time is zero"),
        env.block
            .height
            .try_into()
            .expect("violated invariant: block height is zero"),
        quorum_threshold,
        participants,
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => {
            execute::construct_proof(deps, env, message_ids)
        }
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
            return Ok(Response::default());
        }

        let messages: Vec<Message> = messages
            .into_iter()
            .map(|msg| msg.try_into())
            .collect::<Result<Vec<Message>, ContractError>>()?;

        let command_batch =
            CommandBatch::new(env.block.height, messages, config.destination_chain_id);

        COMMANDS_BATCH.save(deps.storage, &command_batch.id, &command_batch)?;

        let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
            msg: command_batch.msg_to_sign,
        };

        Ok(Response::new().add_message(WasmMsg::Execute {
            contract_addr: config.multisig.into(),
            msg: to_binary(&start_sig_msg)?,
            funds: vec![],
        }))
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
        let proof_id = HexBinary::from_hex(proof_id.as_str())?;

        let batch = COMMANDS_BATCH.load(deps.storage, proof_id.as_slice())?;

        let proof_response = GetProofResponse {
            proof_id: proof_id,
            message_ids: batch.message_ids,
            data: batch.data,
            proof: todo!(),
            execute_data: todo!(),
        };

        Ok(proof_response)
    }
}
