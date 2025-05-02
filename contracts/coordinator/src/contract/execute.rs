use core::cmp::Ordering;
use std::collections::HashSet;

use axelar_wasm_std::counter::Counter;
use cosmwasm_std::{Addr, Binary, DepsMut, Env, Event, MessageInfo, Response, WasmMsg, WasmQuery, StdResult};
use error_stack::{Result, ResultExt, report};
use router_api::{ChainName, ChainEndpoint};
use router_api::msg::QueryMsg;

use crate::msg::DeploymentParams;
use crate::state::{
    load_config, save_chain_contracts, save_prover_for_chain, update_verifier_set_for_prover, INSTANTIATE2_COUNTER,
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to activate verifier set")]
    VerifierSetActivationFailed,

    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),

    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),

    #[error("failed to perform instantiate2")]
    Instantiate2SaltFailure,

    #[error("failed to deploy core contracts")]
    FailedToDeployContracts,

    #[error("chain {0} already taken with gateway {1}")]
    ChainNameTaken(ChainName, Addr),
}

pub fn register_prover(
    deps: DepsMut,
    chain_name: ChainName,
    new_prover_addr: Addr,
) -> Result<Response, Error> {
    save_prover_for_chain(deps.storage, chain_name, new_prover_addr.clone())
        .change_context(Error::ProverNotRegistered(new_prover_addr))?;
    Ok(Response::new())
}

pub fn register_chain(
    deps: DepsMut,
    chain_name: ChainName,
    prover_addr: Addr,
    gateway_addr: Addr,
    voting_verifier_address: Addr,
) -> Result<Response, Error> {
    save_chain_contracts(
        deps.storage,
        chain_name.clone(),
        prover_addr,
        gateway_addr,
        voting_verifier_address,
    )
    .change_context(Error::ChainNotRegistered(chain_name))?;
    Ok(Response::new())
}

pub fn set_active_verifier_set(
    deps: DepsMut,
    info: MessageInfo,
    verifiers: HashSet<Addr>,
) -> Result<Response, Error> {
    update_verifier_set_for_prover(deps.storage, info.sender, verifiers)
        .change_context(Error::VerifierSetActivationFailed)?;
    Ok(Response::new())
}

fn instantiate2_salt(deps: &mut DepsMut, info: &MessageInfo) -> error_stack::Result<Vec<u8>, Error> {
    let counter_value = INSTANTIATE2_COUNTER.cur(deps.storage).to_be_bytes();

    let mut addr_vec = match info.sender.to_string().as_bytes().len().cmp(&counter_value.len()) {
        Ordering::Greater => info.sender.to_string().as_bytes()[..counter_value.len()].to_vec(),
        _ => info.sender.to_string().as_bytes().to_vec(),
    };

    INSTANTIATE2_COUNTER.incr(deps.storage)
    .change_context(Error::Instantiate2SaltFailure)?;

    addr_vec.extend(counter_value);
    Ok(addr_vec)
}

fn instantiate2_addr(
    deps: &DepsMut,
    info: &MessageInfo,
    code_id: u64,
    salt: &[u8],
) -> error_stack::Result<Addr, Error> {
    let code_info: cosmwasm_std::CodeInfoResponse = deps
        .querier
        .query(&WasmQuery::CodeInfo { code_id }.into())
        .change_context(Error::FailedToDeployContracts)?;

    deps.api
        .addr_humanize(
            &cosmwasm_std::instantiate2_address(
                code_info.checksum.as_slice(),
                &deps
                    .api
                    .addr_canonicalize(info.sender.as_str())
                    .change_context(Error::FailedToDeployContracts)?,
                salt,
            )
            .change_context(Error::FailedToDeployContracts)?,
        )
        .change_context(Error::FailedToDeployContracts)
}

fn launch_contract(
    deps: &DepsMut,
    info: &MessageInfo,
    env: &Env,
    salt: Binary,
    code_id: u64,
    instantiate_msg: Binary,
    label: String,
) -> error_stack::Result<(Vec<WasmMsg>, Addr), Error> {
    let mut results = (vec![], Addr::unchecked(""));

    // Instantiate the contract
    results.0.push(WasmMsg::Instantiate2 {
        admin: Some(info.sender.to_string()),
        code_id,
        msg: instantiate_msg,
        funds: info.funds.clone(),
        label,
        salt: salt.clone(),
    });

    // Get Code info
    let code_info: cosmwasm_std::CodeInfoResponse = deps
        .querier
        .query(&WasmQuery::CodeInfo { code_id }.into())
        .change_context(Error::FailedToDeployContracts)?;

    results.1 = deps
        .api
        .addr_humanize(
            &cosmwasm_std::instantiate2_address(
                code_info.checksum.as_slice(),
                &deps
                    .api
                    .addr_canonicalize(&env.contract.address.to_string().clone())
                    .unwrap(),
                salt.as_slice(),
            )
            .map_err(|_| Error::FailedToDeployContracts)?,
        )
        .map_err(|_| Error::FailedToDeployContracts)?;

    Ok(results)
}

pub fn deploy_chain(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    chain_name: ChainName,
    params: &DeploymentParams,
) -> error_stack::Result<Response, Error> {
    let mut response = Response::new();
    let config = load_config(deps.storage);
    
    // if let Ok(chain_endpoint) = deps.querier.query_wasm_smart::<ChainEndpoint>(
    //     config.router.clone(), 
    //     &QueryMsg::ChainInfo(chain_name.clone())
    // ) {
    //     return error_stack::Result::Err(report!(Error::ChainNameTaken(
    //         chain_name,
    //         chain_endpoint.gateway.address
    //     )));
    // }

    let gateway_salt = instantiate2_salt(&mut deps, &info)
    .change_context(Error::FailedToDeployContracts)?;

    let verifier_salt = instantiate2_salt(&mut deps, &info)
    .change_context(Error::FailedToDeployContracts)?;

    let prover_salt = instantiate2_salt(&mut deps, &info)
    .change_context(Error::FailedToDeployContracts)?;

    match params {
        DeploymentParams::Manual {
            gateway_code_id,
            gateway_label,
            prover_code_id,
            prover_label,
            prover_msg,
            verifier_code_id,
            verifier_label,
            verifier_msg,
        } => {
            let verifier_address =
                instantiate2_addr(&deps, &info, *verifier_code_id, verifier_salt.as_ref())?;

            let mut event = Event::new("coordinator_deploy_contracts");

            let (msgs, gateway_address) = launch_contract(
                &deps,
                &info,
                &env,
                Binary::new(gateway_salt),
                *gateway_code_id,
                cosmwasm_std::to_json_binary(&gateway_api::msg::InstantiateMsg {
                    verifier_address: verifier_address.to_string().clone(),
                    router_address: config.router.to_string().clone(),
                })
                .change_context(Error::FailedToDeployContracts)?,
                gateway_label.clone(),
            )?;

            event = event.add_attribute("gateway_address", gateway_address.clone());
            response = response.add_messages(msgs);

            let (msgs, voting_verifier_address) = launch_contract(
                &deps,
                &info,
                &env,
                Binary::new(verifier_salt),
                *verifier_code_id,
                cosmwasm_std::to_json_binary(&voting_verifier_api::msg::InstantiateMsg {
                    governance_address: verifier_msg.governance_address.parse().unwrap(),
                    service_registry_address: config.service_registry.to_string().parse().unwrap(),
                    service_name: verifier_msg.service_name.parse().unwrap(),
                    source_gateway_address: verifier_msg.source_gateway_address.parse().unwrap(),
                    voting_threshold: verifier_msg.voting_threshold,
                    block_expiry: verifier_msg.block_expiry,
                    confirmation_height: verifier_msg.confirmation_height,
                    source_chain: chain_name.clone(),
                    rewards_address: verifier_msg.rewards_address.clone(),
                    msg_id_format: verifier_msg.msg_id_format.clone(),
                    address_format: verifier_msg.address_format.clone(),
                })
                .change_context(Error::FailedToDeployContracts)?,
                verifier_label.clone(),
            )?;

            event = event.add_attribute("voting_verifier_address", voting_verifier_address.clone());
            response = response.add_messages(msgs);

            let (msgs, multisig_prover_address) = launch_contract(
                &deps,
                &info,
                &env,
                Binary::new(prover_salt),
                *prover_code_id,
                cosmwasm_std::to_json_binary(&multisig_prover_api::msg::InstantiateMsg {
                    admin_address: info.sender.to_string().clone(),
                    governance_address: prover_msg.governance_address.to_string().clone(),
                    coordinator_address: env.contract.address.to_string().clone(),
                    gateway_address: gateway_address.to_string().clone(),
                    multisig_address: config.multisig.to_string().clone(),
                    service_registry_address: config.service_registry.to_string().clone(),
                    voting_verifier_address: voting_verifier_address.to_string().clone(),
                    signing_threshold: prover_msg.signing_threshold,
                    service_name: prover_msg.service_name.to_string(),
                    chain_name: chain_name.to_string().clone(),
                    verifier_set_diff_threshold: prover_msg.verifier_set_diff_threshold,
                    encoder: prover_msg.encoder,
                    key_type: prover_msg.key_type,
                    domain_separator: prover_msg.domain_separator,
                })
                .change_context(Error::FailedToDeployContracts)?,
                prover_label.clone(),
            )?;

            event = event.add_attribute("multisig_prover_address", multisig_prover_address);
            response = response.add_messages(msgs).add_event(event);
        }
    }

    Ok(response)
}
