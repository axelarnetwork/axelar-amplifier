use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response};
use error_stack::ResultExt;
use multisig::key::PublicKey;

mod execute;
mod query;
mod reply;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{
    Config, AVAILABLE_TICKETS, CONFIG, FEE_RESERVE, LAST_ASSIGNED_TICKET_NUMBER,
    LATEST_SEQUENTIAL_UNSIGNED_TX_HASH, NEXT_SEQUENCE_NUMBER,
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
        xrpl_transaction_fee: msg.xrpl_transaction_fee,
        xrpl_base_reserve: msg.xrpl_base_reserve,
        xrpl_owner_reserve: msg.xrpl_owner_reserve,
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
    FEE_RESERVE.save(deps.storage, &msg.initial_fee_reserve)?;

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
    let gateway: xrpl_gateway::Client =
        client::ContractClient::new(deps.querier, &config.gateway).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::TrustSet { token_id } => execute::construct_trust_set_proof(
            deps.storage,
            gateway,
            env.contract.address,
            &config,
            token_id,
        ),
        ExecuteMsg::ConstructProof { cc_id, payload } => execute::construct_payment_proof(
            deps.storage,
            deps.querier,
            gateway,
            env.contract.address,
            env.block.height,
            &config,
            cc_id,
            payload,
        ),
        ExecuteMsg::UpdateVerifierSet => {
            execute::update_verifier_set(deps.storage, deps.querier, env)
        }
        ExecuteMsg::ConfirmProverMessage { prover_message } => {
            execute::confirm_prover_message(deps.storage, deps.querier, &config, prover_message)
        }
        ExecuteMsg::TicketCreate => {
            execute::construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => execute::update_signing_threshold(deps, new_signing_threshold),
        ExecuteMsg::UpdateXrplTransactionFee {
            new_transaction_fee,
        } => execute::update_xrpl_transaction_fee(deps, new_transaction_fee),
        ExecuteMsg::UpdateXrplReserves {
            new_base_reserve,
            new_owner_reserve,
        } => execute::update_xrpl_reserves(deps, new_base_reserve, new_owner_reserve),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            execute::update_admin(deps, new_admin_address)
        }
        ExecuteMsg::ConfirmAddReservesMessage {
            add_reserves_message,
        } => execute::confirm_add_reserves_message(
            deps.storage,
            deps.querier,
            &config,
            add_reserves_message,
        ),
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
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(
            deps.storage,
            deps.querier,
            &config.multisig,
            multisig_session_id,
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
        QueryMsg::CurrentVerifierSet => to_json_binary(&query::current_verifier_set(deps.storage)?),
        QueryMsg::NextVerifierSet => to_json_binary(&query::next_verifier_set(deps.storage)?),
        QueryMsg::MultisigSession { cc_id } => {
            to_json_binary(&query::multisig_session(deps.storage, &cc_id)?)
        }
        QueryMsg::TicketCreate => to_json_binary(&query::ticket_create(
            deps.storage,
            config.ticket_count_threshold,
        )?),
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
        xrpl_transaction_fee: msg.xrpl_transaction_fee,
        xrpl_base_reserve: msg.xrpl_base_reserve,
        xrpl_owner_reserve: msg.xrpl_owner_reserve,
        ticket_count_threshold: msg.ticket_count_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    LATEST_SEQUENTIAL_UNSIGNED_TX_HASH.remove(deps.storage);
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;
    FEE_RESERVE.save(deps.storage, &msg.initial_fee_reserve)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
