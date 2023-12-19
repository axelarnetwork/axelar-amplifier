use std::str::FromStr;

#[cfg(not(feature = "library"))]
use axelar_wasm_std::Threshold;
use connection_router::state::{CrossChainId, ChainName};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    entry_point, Storage, wasm_execute, SubMsg, Reply,
    DepsMut, Env, MessageInfo, Response, Fraction, Uint64, to_binary, Deps, StdResult, Binary, Addr,
};
use xrpl_voting_verifier::execute::MessageStatus;

use crate::{
    error::ContractError,
    state::{Config, CONFIG, REPLY_TX_HASH, TOKENS, CURRENT_WORKER_SET, NEXT_WORKER_SET, SIGNED_TO_UNSIGNED_TX_HASH},
    reply,
    types::*,
    xrpl_multisig::{self, XRPLPaymentAmount, XRPLTokenAmount}, axelar_workers, querier::{Querier, XRPL_CHAIN_NAME}, query::{get_proof, GetProofResponse, QueryMsg, self},
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cw_serde]
pub struct InstantiateMsg {
    axelar_multisig_address: String,
    gateway_address: String,
    signing_threshold: Threshold,
    xrpl_multisig_address: String,
    voting_verifier_address: String,
    service_registry_address: String,
    service_name: String,
    worker_set_diff_threshold: u32,
    xrpl_fee: u64,
    ticket_count_threshold: u32,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let axelar_multisig_address = deps.api.addr_validate(&msg.axelar_multisig_address)?;
    let gateway_address = deps.api.addr_validate(&msg.gateway_address)?;
    let xrpl_multisig_address = deps.api.addr_validate(&msg.xrpl_multisig_address)?;
    let voting_verifier_address = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry_address = deps.api.addr_validate(&msg.service_registry_address)?;

    if msg.signing_threshold.numerator() > u32::MAX.into() {
        return Err(ContractError::InvalidSigningThreshold.into());
    }

    let config = Config {
        axelar_multisig_address,
        gateway_address,
        xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
        voting_verifier_address,
        service_registry_address,
        service_name: msg.service_name,
        worker_set_diff_threshold: msg.worker_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
    };

    CONFIG.save(deps.storage, &config)?;

    let querier = Querier::new(deps.querier, config.clone());
    let new_worker_set = axelar_workers::get_active_worker_set(querier, msg.signing_threshold, env.block.height)?;

    CURRENT_WORKER_SET.save(deps.storage, &new_worker_set)?;

    Ok(Response::new().add_message(wasm_execute(
        config.axelar_multisig_address,
        &multisig::msg::ExecuteMsg::RegisterWorkerSet {
            worker_set: new_worker_set.into(),
        },
        vec![],
    )?))
}

#[cw_serde]
pub enum ExecuteMsg {
    ConstructProof(CrossChainId),
    FinalizeProof(Uint64),
    UpdateTxStatus(CrossChainId, MessageStatus),
    UpdateWorkerSet(),
    TicketCreate(),
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());

    let res = match msg {
        ExecuteMsg::ConstructProof(message_id) => {
            construct_payment_proof(deps.storage, querier, info, env.contract.address, &config, message_id)
        },
        ExecuteMsg::FinalizeProof(session_id) => {
            finalize_proof(deps.storage, querier, &session_id)
        }
        ExecuteMsg::UpdateWorkerSet() => {
            construct_signer_list_set_proof(deps.storage, querier, env, &config)
        },
        ExecuteMsg::UpdateTxStatus(cc_id, status) => {
            update_tx_status(deps.storage, querier, cc_id, &status)
        },
        ExecuteMsg::TicketCreate() => {
            construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        },
    }?;

    Ok(res)
}

fn finalize_proof(
    storage: &mut dyn Storage,
    querier: Querier,
    multisig_session_id: &Uint64
) -> Result<Response, ContractError> {
    match get_proof(storage, querier, multisig_session_id)? {
        GetProofResponse::Pending { unsigned_tx_hash: _ } => {
            Err(ContractError::SigningSessionNotCompleted)
        },
        GetProofResponse::Completed { unsigned_tx_hash, tx_blob } => {
            let tx_hash = xrpl_multisig::compute_signed_tx_hash(tx_blob.as_slice().to_vec())?;
            SIGNED_TO_UNSIGNED_TX_HASH.save(storage, tx_hash, &unsigned_tx_hash)?;
            Ok(Response::default()) 
        }
    }
}

fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: Querier,
    info: MessageInfo,
    self_address: Addr,
    config: &Config,
    message_id: CrossChainId,
) -> Result<Response, ContractError> {
    if info.funds.len() != 1 {
        return Err(ContractError::InvalidPaymentAmount);
    }

    let mut funds = info.funds;
    let coin = funds.remove(0);
    let xrpl_token = TOKENS.load(storage, coin.denom.clone())?;
    let message = querier.get_message(message_id.clone())?;
    let drops = u64::try_from(coin.amount.u128() / 10u128.pow(12)).map_err(|_| ContractError::InvalidAmount)?;
    let xrpl_payment_amount = if xrpl_token.currency == XRPLToken::NATIVE_CURRENCY {
        XRPLPaymentAmount::Drops(drops)
    } else {
        XRPLPaymentAmount::Token(
            XRPLToken {
                issuer: xrpl_token.issuer,
                currency: xrpl_token.currency,
            },
            XRPLTokenAmount(drops.to_string()),
        )
    };

    let tx_hash = xrpl_multisig::issue_payment(
        storage,
        config,
        message.destination_address.to_string().try_into()?,
        xrpl_payment_amount,
        message_id,
    )?;

    Ok(
        start_signing_session(
            storage,
            config,
            tx_hash,
            self_address
        )?
    )
}

pub fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    tx_hash: TxHash,
    self_address: Addr,
) -> Result<Response, ContractError> {
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    let cur_worker_set = CURRENT_WORKER_SET.load(storage)?;
    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        worker_set_id: cur_worker_set.id(),
        chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
        msg: tx_hash.into(),
        sig_verifier: Some(self_address.into())
    };

    let wasm_msg = wasm_execute(config.axelar_multisig_address.clone(), &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn construct_signer_list_set_proof(
    storage: &mut dyn Storage,
    querier: Querier,
    env: Env,
    config: &Config,
) -> Result<Response, ContractError> {
    if !CURRENT_WORKER_SET.exists(storage) {
        return Err(ContractError::WorkerSetIsNotSet.into())
    }

    let new_worker_set = axelar_workers::get_active_worker_set(querier, config.signing_threshold, env.block.height)?;
    let cur_worker_set = CURRENT_WORKER_SET.load(storage)?;
    if !axelar_workers::should_update_worker_set(
        &new_worker_set,
        &cur_worker_set,
        config.worker_set_diff_threshold as usize,
    ) {
        return Err(ContractError::WorkerSetUnchanged.into())
    }

    let tx_hash = xrpl_multisig::issue_signer_list_set(
        storage,
        config,
        cur_worker_set,
    )?;

    NEXT_WORKER_SET.save(storage, tx_hash.clone(), &new_worker_set)?;

    Ok(
        start_signing_session(
            storage,
            config,
            tx_hash,
            env.contract.address
        )?
    )
}

fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::available_ticket_count(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached.into());
    }

    let tx_hash = xrpl_multisig::issue_ticket_create(
        storage,
        config,
        ticket_count,
    )?;

    let response = start_signing_session(
        storage,
        config,
        tx_hash,
        self_address
    )?;

    Ok(response)
}

fn update_tx_status(
    storage: &mut dyn Storage,
    querier: Querier,
    cc_id: CrossChainId,
    status: &MessageStatus
) -> Result<Response, ContractError> {
    if !querier.get_message_confirmation(cc_id.clone(), status)? {
        return Err(ContractError::InvalidMessageStatus)
    }

    let tx_hash: TxHash = TxHash::try_from(cc_id)?;

    xrpl_multisig::update_tx_status(storage, tx_hash, status.clone().into())?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());
    match msg {
        QueryMsg::GetProof {
            multisig_session_id,
        } => to_binary(&query::get_proof(deps.storage, querier, &multisig_session_id)?),
    }
}