use std::str::FromStr;

#[cfg(not(feature = "library"))]
use axelar_wasm_std::{Threshold, VerificationStatus};
use connection_router::{state::{Address, ChainName, CrossChainId}, Message};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    entry_point, Storage, wasm_execute, SubMsg, Reply,
    DepsMut, Env, MessageInfo, Response, Fraction, Uint64, to_binary, Deps, StdResult, Binary, Addr, HexBinary,
};
use multisig::types::MultisigState;

use crate::{
    axelar_workers, error::ContractError, msg::{ExecuteMsg, QueryMsg}, querier::{Querier, XRPL_CHAIN_NAME}, query, reply, state::{Config, AVAILABLE_TICKETS, CONFIG, CURRENT_WORKER_SET, LAST_ASSIGNED_TICKET_NUMBER, MESSAGE_ID_TO_MULTISIG_SESSION_ID, MULTISIG_SESSION_TX, NEXT_SEQUENCE_NUMBER, NEXT_WORKER_SET, REPLY_MESSAGE_ID, REPLY_TX_HASH, TOKENS, TRANSACTION_INFO}, types::*, xrpl_multisig::{self, XRPLPaymentAmount, XRPLSerialize, XRPLTokenAmount}
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cw_serde]
pub struct InstantiateMsg {
    pub axelar_multisig_address: String,
    pub gateway_address: String,
    pub signing_threshold: Threshold,
    pub xrpl_multisig_address: String,
    pub voting_verifier_address: String,
    pub service_registry_address: String,
    pub service_name: String,
    pub worker_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
    pub available_tickets: Vec<u32>,
    pub next_sequence_number: u32,
    pub last_assigned_ticket_number: u32,
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
    let voting_verifier_address = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry_address = deps.api.addr_validate(&msg.service_registry_address)?;

    if msg.signing_threshold.numerator() > u32::MAX.into() {
        return Err(ContractError::InvalidSigningThreshold.into());
    }

    let config = Config {
        axelar_multisig_address,
        gateway_address,
        xrpl_multisig_address: msg.xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
        voting_verifier_address,
        service_registry_address,
        service_name: msg.service_name,
        worker_set_diff_threshold: msg.worker_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
        key_type: multisig::key::KeyType::Ecdsa,
    };

    CONFIG.save(deps.storage, &config)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    let querier = Querier::new(deps.querier, config.clone());
    let new_worker_set = axelar_workers::get_active_worker_set(querier, msg.signing_threshold, env.block.height)?;

    CURRENT_WORKER_SET.save(deps.storage, &new_worker_set)?;

    let msg = wasm_execute(
        config.axelar_multisig_address,
        &multisig::msg::ExecuteMsg::RegisterWorkerSet {
            worker_set: new_worker_set.into(),
        },
        vec![],
    )?;

    Ok(Response::new().add_message(msg))
}

fn register_token(
    storage: &mut dyn Storage,
    denom: String,
    token: &XRPLToken,
) -> Result<Response, ContractError> {
    TOKENS.save(storage, denom, token)?;
    Ok(Response::default())
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
        // TODO: should be admin-only
        ExecuteMsg::RegisterToken { denom, token } => {
            register_token(deps.storage, denom, &token)
        },
        ExecuteMsg::ConstructProof { message_id } => {
            construct_payment_proof(deps.storage, querier, info, env.contract.address, env.block.height, &config, message_id)
        },
        ExecuteMsg::UpdateWorkerSet {} => {
            construct_signer_list_set_proof(deps.storage, querier, env, &config)
        },
        ExecuteMsg::UpdateTxStatus { multisig_session_id, signers, message_id, message_status } => {
            update_tx_status(deps.storage, querier, &multisig_session_id, &signers, &message_id, message_status, config.axelar_multisig_address, config.xrpl_multisig_address)
        },
        ExecuteMsg::TicketCreate {} => {
            construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        },
    }?;

    Ok(res)
}

fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: Querier,
    info: MessageInfo,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    message_id: CrossChainId,
) -> Result<Response, ContractError> {
    if info.funds.len() != 1 {
        return Err(ContractError::InvalidPaymentAmount);
    }

    match MESSAGE_ID_TO_MULTISIG_SESSION_ID.may_load(storage, message_id.clone())? {
        Some(multisig_session_id) => {
            let multisig_session = querier.get_multisig_session(Uint64::from(multisig_session_id))?;
            if let MultisigState::Completed { .. } = multisig_session.state {
                return Err(ContractError::PaymentAlreadySigned);
            }

            if multisig_session.expires_at <= block_height {
                return Err(ContractError::PaymentAlreadyHasActiveSigningSession);
            }
        },
        None => (),
    };

    let mut funds = info.funds;
    let coin = funds.remove(0);
    let xrpl_token = TOKENS.load(storage, coin.denom.clone())?;
    let message = querier.get_message(message_id.clone())?;
    let xrpl_payment_amount = if xrpl_token.currency == XRPLToken::NATIVE_CURRENCY {
        let drops = u64::try_from(coin.amount.u128()).map_err(|_| ContractError::InvalidAmount { amount: coin.amount.to_string(), reason: "overflow".to_string() })?;
        XRPLPaymentAmount::Drops(drops)
    } else {
        XRPLPaymentAmount::Token(
            XRPLToken {
                issuer: xrpl_token.issuer,
                currency: xrpl_token.currency,
            },
            XRPLTokenAmount(coin.amount.to_string()),
        )
    };

    let tx_hash = xrpl_multisig::issue_payment(
        storage,
        config,
        message.destination_address.to_string().try_into()?,
        xrpl_payment_amount,
        message_id.clone(),
    )?;

    REPLY_MESSAGE_ID.save(storage, &message_id)?;
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
    _self_address: Addr,
) -> Result<Response, ContractError> {
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    let cur_worker_set: multisig::worker_set::WorkerSet = CURRENT_WORKER_SET.load(storage)?.into();
    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        worker_set_id: cur_worker_set.id(),
        chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
        msg: tx_hash.into(),
        // TODO: implement sig_verifier
        //sig_verifier: Some(self_address.into())
        sig_verifier: None,
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
    multisig_session_id: &Uint64,
    signers: &Vec<Addr>,
    message_id: &CrossChainId,
    status: VerificationStatus,
    axelar_multisig_address: impl Into<String>,
    xrpl_multisig_address: String,
) -> Result<Response, ContractError> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;
    let tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;
    let multisig_session = querier.get_multisig_session(multisig_session_id.clone())?;
    let message = Message {
        destination_chain: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
        source_address: Address::from_str(&xrpl_multisig_address).map_err(|_| ContractError::InvalidAddress)?,
        destination_address: Address::from_str(match &tx_info.unsigned_contents {
            xrpl_multisig::XRPLUnsignedTx::Payment(p) => p.destination.as_str(),
            _ => &xrpl_multisig_address,
        }).map_err(|_| ContractError::InvalidAddress)?,
        cc_id: message_id.clone(),
        payload_hash: [0; 32],
    };

    let axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)> = multisig_session.signers
        .iter()
        .filter(|(signer, signature)| signature.is_some() && signers.contains(&signer.address))
        .map(|(signer, signature)| (signer.clone(), signature.clone().unwrap()))
        .collect();

    if axelar_signers.len() != signers.len() {
        return Err(ContractError::SignatureNotFound);
    }

    let signed_tx = query::make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers, multisig_session_id)?; // TODO: RELOCATE FUNCTION
    let tx_blob = HexBinary::from(signed_tx.xrpl_serialize()?);
    let tx_hash: HexBinary = TxHash::from(xrpl_multisig::compute_signed_tx_hash(tx_blob.as_slice().to_vec())?).into();

    let actual_status = querier.get_message_status(message)?;
    if parse_message_id(&message_id.id)?.0.to_string() != tx_hash.to_string() {
        return Err(ContractError::InvalidMessageID(message_id.id.to_string()));
    }

    if status != actual_status {
        return Err(ContractError::InvalidMessageStatus)
    }

    match xrpl_multisig::update_tx_status(storage, axelar_multisig_address, unsigned_tx_hash, status.clone().into())? {
        None => Ok(Response::default()),
        Some(msg) => Ok(Response::new().add_message(msg))
    }
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
        QueryMsg::GetMessageToSign {
            multisig_session_id,
            signer_xrpl_address,
        } => to_binary(&query::get_message_to_sign(deps.storage, &multisig_session_id, &signer_xrpl_address)?),
        QueryMsg::GetWorkerSet {} => to_binary(&query::get_worker_set(deps.storage)?),
    }
}
