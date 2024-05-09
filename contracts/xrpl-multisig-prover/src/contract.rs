use std::str::FromStr;

#[cfg(not(feature = "library"))]
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use connection_router_api::{Address, ChainName, CrossChainId, Message};
use cosmwasm_std::{
    entry_point, to_json_binary, wasm_execute, Addr, Binary, Deps, DepsMut, Env, Fraction,
    HexBinary, MessageInfo, Reply, Response, StdResult, Storage, SubMsg, Uint64,
};
// TODO: create custom message ID format
use voting_verifier::events::parse_message_id;

use multisig::{key::PublicKey, types::MultisigState};

use crate::{
    axelar_workers,
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg},
    querier::{Querier, XRPL_CHAIN_NAME},
    query, reply,
    state::{
        Config, AVAILABLE_TICKETS, CONFIG, CURRENT_WORKER_SET, LAST_ASSIGNED_TICKET_NUMBER,
        MESSAGE_ID_TO_MULTISIG_SESSION_ID, MULTISIG_SESSION_ID_TO_TX_HASH, NEXT_SEQUENCE_NUMBER,
        NEXT_WORKER_SET, REPLY_MESSAGE_ID, REPLY_TX_HASH, TOKENS, TRANSACTION_INFO,
    },
    types::*,
    xrpl_multisig,
    xrpl_serialize::XRPLSerialize,
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = make_config(&deps, msg.clone())?;
    CONFIG.save(deps.storage, &config)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    let querier = Querier::new(deps.querier, config.clone());
    let new_worker_set =
        axelar_workers::get_active_worker_set(&querier, msg.signing_threshold, env.block.height)?;

    CURRENT_WORKER_SET.save(deps.storage, &new_worker_set.clone())?;

    Ok(Response::new()
        .add_message(wasm_execute(
            config.axelar_multisig,
            &multisig::msg::ExecuteMsg::RegisterWorkerSet {
                worker_set: new_worker_set.clone().into(),
            },
            vec![],
        )?)
        .add_message(wasm_execute(
            config.monitoring,
            &monitoring::msg::ExecuteMsg::SetActiveVerifiers {
                next_worker_set: new_worker_set.into(),
            },
            vec![],
        )?))
}

fn make_config(
    deps: &DepsMut,
    msg: InstantiateMsg,
) -> Result<Config, axelar_wasm_std::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let relayer = deps.api.addr_validate(&msg.relayer_address)?;
    let axelar_multisig = deps.api.addr_validate(&msg.axelar_multisig_address)?;
    let monitoring = deps.api.addr_validate(&msg.monitoring_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    if msg.signing_threshold.numerator() > u32::MAX.into()
        || msg.signing_threshold.denominator() == Uint64::zero()
    {
        return Err(ContractError::InvalidSigningThreshold.into());
    }

    Ok(Config {
        admin,
        governance,
        relayer,
        axelar_multisig,
        monitoring,
        gateway,
        xrpl_multisig: msg.xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
        voting_verifier,
        service_registry,
        service_name: msg.service_name,
        worker_set_diff_threshold: msg.worker_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
        key_type: multisig::key::KeyType::Ecdsa,
        xrp_denom: msg.xrp_denom,
    })
}

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.admin {
        admin if admin == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.governance {
        governance if governance == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn require_permissioned_relayer(
    deps: &DepsMut,
    info: MessageInfo,
) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.relayer {
        governance if governance == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

fn register_token(
    storage: &mut dyn Storage,
    denom: String,
    token: &XRPLToken,
    decimals: u8,
) -> Result<Response, ContractError> {
    TOKENS.save(storage, &denom, &(token.clone(), decimals))?;
    Ok(Response::default())
}

pub fn update_signing_threshold(
    deps: DepsMut,
    new_signing_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.signing_threshold = new_signing_threshold;
            Ok(config)
        },
    )?;
    Ok(Response::new())
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
        ExecuteMsg::RegisterToken {
            denom,
            token,
            decimals,
        } => {
            require_admin(&deps, info.clone())
                .or_else(|_| require_governance(&deps, info.clone()))?;
            register_token(deps.storage, denom, &token, decimals)
        }
        // TODO: coin should be info.funds
        ExecuteMsg::ConstructProof { message_id, coin } => {
            require_permissioned_relayer(&deps, info)?;
            construct_payment_proof(
                deps.storage,
                &querier,
                env.contract.address,
                env.block.height,
                &config,
                message_id,
                &coin,
            )
        }
        ExecuteMsg::UpdateWorkerSet {} => {
            require_admin(&deps, info.clone()).or_else(|_| require_governance(&deps, info))?;
            construct_signer_list_set_proof(deps.storage, &querier, env, &config)
        }
        ExecuteMsg::UpdateTxStatus {
            multisig_session_id,
            signer_public_keys,
            message_id,
            message_status,
        } => update_tx_status(
            deps.storage,
            &querier,
            &config,
            &multisig_session_id,
            &signer_public_keys,
            &message_id,
            message_status,
        ),
        ExecuteMsg::TicketCreate {} => {
            construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => {
            require_governance(&deps, info)?;
            update_signing_threshold(deps, new_signing_threshold)
        }
    }?;

    Ok(res)
}

fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    message_id: CrossChainId,
    coin: &cosmwasm_std::Coin,
) -> Result<Response, ContractError> {
    // if info.funds.len() != 1 {
    if coin.amount == cosmwasm_std::Uint128::zero() {
        return Err(ContractError::InvalidPaymentAmount);
    }

    // Prevent creating a duplicate signing session before the previous one expires
    if let Some(multisig_session_id) =
        MESSAGE_ID_TO_MULTISIG_SESSION_ID.may_load(storage, &message_id)?
    {
        let multisig_session = querier.get_multisig_session(&Uint64::from(multisig_session_id))?;
        if multisig_session.state == MultisigState::Pending
            && multisig_session.expires_at <= block_height
        {
            return Err(ContractError::PaymentAlreadyHasActiveSigningSession(
                multisig_session_id,
            ));
        }
    };

    let message = querier.get_message(&message_id)?;
    let xrpl_payment_amount = if coin.denom == config.xrp_denom {
        let drops =
            u64::try_from(coin.amount.u128()).map_err(|_| ContractError::InvalidAmount {
                reason: "overflow".to_string(),
            })?;
        XRPLPaymentAmount::Drops(drops)
    } else {
        let (xrpl_token, decimals) = TOKENS.load(storage, &coin.denom)?;
        // TODO: handle decimal precision conversion between CosmWasm Coin and XRPLToken
        XRPLPaymentAmount::Token(xrpl_token, canonicalize_coin_amount(coin.amount, decimals)?)
    };

    let tx_hash = xrpl_multisig::issue_payment(
        storage,
        config,
        message.destination_address.to_string().try_into()?,
        &xrpl_payment_amount,
        &message_id,
    )?;

    REPLY_MESSAGE_ID.save(storage, &message_id)?;
    start_signing_session(storage, config, tx_hash, self_address)
}

pub fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    tx_hash: TxHash,
    self_address: Addr,
) -> Result<Response, ContractError> {
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    let cur_worker_set_id = match CURRENT_WORKER_SET.may_load(storage)? {
        Some(worker_set) => Into::<multisig::worker_set::WorkerSet>::into(worker_set).id(),
        None => {
            return Err(ContractError::NoWorkerSet);
        }
    };

    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        worker_set_id: cur_worker_set_id,
        chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
        msg: tx_hash.into(),
        sig_verifier: Some(self_address.into()),
    };

    let wasm_msg = wasm_execute(&config.axelar_multisig, &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn construct_signer_list_set_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: Env,
    config: &Config,
) -> Result<Response, ContractError> {
    if !CURRENT_WORKER_SET.exists(storage) {
        return Err(ContractError::WorkerSetIsNotSet);
    }

    let new_worker_set =
        axelar_workers::get_active_worker_set(querier, config.signing_threshold, env.block.height)?;
    let cur_worker_set = CURRENT_WORKER_SET.load(storage)?;
    if !axelar_workers::should_update_worker_set(
        &new_worker_set.clone().into(),
        &cur_worker_set.clone().into(),
        usize::try_from(config.worker_set_diff_threshold).unwrap(),
    ) {
        return Err(ContractError::WorkerSetUnchanged);
    }

    let tx_hash = xrpl_multisig::issue_signer_list_set(storage, config, cur_worker_set)?;

    NEXT_WORKER_SET.save(storage, &tx_hash, &new_worker_set)?;

    start_signing_session(storage, config, tx_hash, env.contract.address)
}

fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::tickets_available_to_request(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    let tx_hash = xrpl_multisig::issue_ticket_create(storage, config, ticket_count)?;

    let response = start_signing_session(storage, config, tx_hash, self_address)?;

    Ok(response)
}

fn update_tx_status(
    storage: &mut dyn Storage,
    querier: &Querier,
    config: &Config,
    multisig_session_id: &Uint64,
    signer_public_keys: &[PublicKey],
    message_id: &CrossChainId,
    status: VerificationStatus,
) -> Result<Response, ContractError> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_TX_HASH.load(storage, multisig_session_id.u64())?;
    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    let multisig_session = querier.get_multisig_session(multisig_session_id)?;

    let destination_str = match &tx_info.unsigned_contents {
        XRPLUnsignedTx::Payment(p) => p.destination.to_string(),
        _ => config.xrpl_multisig.to_string(),
    };

    let message = Message {
        destination_chain: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
        source_address: Address::from_str(&config.xrpl_multisig.to_string())
            .map_err(|_| ContractError::InvalidAddress)?,
        destination_address: Address::from_str(destination_str.as_ref())
            .map_err(|_| ContractError::InvalidAddress)?,
        cc_id: message_id.clone(),
        payload_hash: [0; 32],
    };

    let xrpl_signers: Vec<XRPLSigner> = multisig_session
        .signers
        .iter()
        .filter(|(signer, _)| signer_public_keys.contains(&signer.pub_key))
        .filter_map(|(signer, signature)| {
            signature
                .as_ref()
                .map(|signature| XRPLSigner::try_from((signer.clone(), signature.clone())))
        })
        .collect::<Result<Vec<_>, ContractError>>()?;

    if xrpl_signers.len() != signer_public_keys.len() {
        return Err(ContractError::SignatureNotFound);
    }

    let signed_tx = XRPLSignedTransaction::new(tx_info.unsigned_contents, xrpl_signers);
    let tx_blob = HexBinary::from(signed_tx.xrpl_serialize()?);
    let tx_hash: HexBinary = xrpl_multisig::compute_signed_tx_hash(tx_blob.as_slice())?.into();

    if parse_message_id(&message_id.id)
        .map_err(|_| ContractError::InvalidMessageID(message_id.id.to_string()))?
        .0
        .to_string()
        != tx_hash.to_string()
    {
        return Err(ContractError::InvalidMessageID(message_id.id.to_string()));
    }

    let actual_status = querier.get_message_status(message)?;
    if status != actual_status {
        return Err(ContractError::InvalidMessageStatus);
    }

    xrpl_multisig::update_tx_status(storage, config, unsigned_tx_hash, status.into())
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
        } => to_json_binary(&query::get_proof(
            deps.storage,
            querier,
            &multisig_session_id,
        )?),
        QueryMsg::VerifySignature {
            session_id,
            message: _,
            public_key,
            signature,
            signer_address: _,
        } => to_json_binary(&query::verify_signature(
            deps.storage,
            &session_id,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        )?),
        QueryMsg::GetWorkerSet {} => to_json_binary(&query::get_worker_set(deps.storage)?),
        QueryMsg::GetMultisigSessionId { message_id } => {
            to_json_binary(&query::get_multisig_session_id(deps.storage, &message_id)?)
        } // TODO: rename
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config = CONFIG.load(deps.storage)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let new_config = Config {
        governance,
        ..old_config
    };
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}
