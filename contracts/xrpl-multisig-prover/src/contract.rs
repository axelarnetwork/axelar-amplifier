use axelar_wasm_std::{address, permission_control, FnExt};
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response};
use error_stack::ResultExt;
use multisig::key::PublicKey;

mod execute;
mod query;
mod reply;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::querier::Querier;
use crate::state::{
    Config, AVAILABLE_TICKETS, CONFIG, LAST_ASSIGNED_TICKET_NUMBER, NEXT_SEQUENCE_NUMBER,
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        gateway: address::validate_cosmwasm_address(deps.api, &msg.gateway_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
        coordinator: address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?,
        service_registry: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        voting_verifier: address::validate_cosmwasm_address(
            deps.api,
            &msg.voting_verifier_address,
        )?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_multisig: msg.xrpl_multisig_address,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(deps.storage, &deps.api.addr_validate(&msg.admin_address)?)?;
    permission_control::set_governance(
        deps.storage,
        &deps.api.addr_validate(&msg.governance_address)?,
    )?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");
    let querier = Querier::new(deps.querier, config.clone());

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::TrustSet { token_id } => execute::construct_trust_set_proof(
            deps.storage,
            &querier,
            env.contract.address,
            &config,
            token_id,
        ),
        ExecuteMsg::ConstructProof { cc_id, payload } => execute::construct_payment_proof(
            deps.storage,
            &querier,
            env.contract.address,
            env.block.height,
            &config,
            cc_id,
            payload,
        ),
        ExecuteMsg::UpdateVerifierSet {} => {
            execute::update_verifier_set(deps.storage, &querier, env)
        }
        ExecuteMsg::ConfirmProverMessage { prover_message } => {
            execute::confirm_prover_message(deps.storage, &querier, &config, prover_message)
        }
        ExecuteMsg::TicketCreate {} => {
            execute::construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => execute::update_signing_threshold(deps, new_signing_threshold),
        ExecuteMsg::UpdateXrplFee { new_xrpl_fee } => execute::update_xrpl_fee(deps, new_xrpl_fee),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            execute::update_admin(deps, new_admin_address)
        }
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(deps.storage, querier, &multisig_session_id)?),
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
        QueryMsg::CurrentVerifierSet {} => {
            to_json_binary(&query::current_verifier_set(deps.storage)?)
        }
        QueryMsg::NextVerifierSet {} => to_json_binary(&query::next_verifier_set(deps.storage)?),
        QueryMsg::MultisigSession { cc_id } => {
            to_json_binary(&query::multisig_session(deps.storage, &cc_id)?)
        }
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    CONFIG.remove(deps.storage);

    let config = Config {
        gateway: address::validate_cosmwasm_address(deps.api, &msg.gateway_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
        coordinator: address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?,
        service_registry: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        voting_verifier: address::validate_cosmwasm_address(
            deps.api,
            &msg.voting_verifier_address,
        )?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_multisig: msg.xrpl_multisig_address,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
