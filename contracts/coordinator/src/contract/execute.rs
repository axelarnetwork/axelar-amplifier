use std::collections::HashSet;
use core::cmp::Ordering;

use error_stack::{Result, ResultExt};
use cosmwasm_std::{Addr, Binary, DepsMut, MessageInfo, Response, WasmMsg, WasmQuery};

use gateway_api::msg::InstantiateMsg as GatewayInstantiateMsg;
use voting_verifier_api::msg::InstantiateMsg as VerifierInstantiateMsg;
use multisig_prover_api::msg::InstantiateMsg as ProverInstantiateMsg;
use router_api::ChainName;

use crate::events::Event;
use crate::state::{save_chain_contracts, save_prover_for_chain, update_verifier_set_for_prover};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to activate verifier set")]
    VerifierSetActivationFailed,

    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),

    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),

    #[error("failed to deploy core contracts")]
    FailedToDeployContracts,
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

fn instantiate2_salt(
    info: &MessageInfo,
) -> Vec<u8> {
    // Temporary. Use a counter instead
    let mut bh_vec = (1 as u32).to_le_bytes().to_vec();
    let mut addr_vec = match info.sender.to_string().as_bytes().len().cmp(&56) {
        Ordering::Greater => {
            info.sender.to_string().as_bytes()[..56].to_vec()
        },
        _ => {
            info.sender.to_string().as_bytes().to_vec()
        },
    };

    addr_vec.append(&mut bh_vec);
    addr_vec
}

fn launch_contract(
    deps: &DepsMut,
    info: &MessageInfo,
    salt: Binary,
    code_id: u64,
    instantiate_msg: Binary,
    label: String,
) -> error_stack::Result<(Vec<WasmMsg>, Vec<Event>), Error> {
    let mut results = (vec![], vec![]);

    // Instantiate the contract
    results.0.push(WasmMsg::Instantiate2 { 
        admin: Some(info.sender.to_string()), 
        code_id: code_id, 
        msg: instantiate_msg, 
        funds: info.funds.clone(), 
        label: label,
        salt: salt.clone(),
    });

    // Get Code info
    let code_info: cosmwasm_std::CodeInfoResponse = deps.querier.query(
        &WasmQuery::CodeInfo { 
            code_id: code_id 
    }.into())
    .change_context(Error::FailedToDeployContracts)?;

    let instantiate2_addr = deps.api.addr_humanize(
        &cosmwasm_std::instantiate2_address(
            code_info.checksum.as_slice(), 
            &info.sender.as_bytes().into(), 
            salt.as_slice()
        ).map_err(|_| Error::FailedToDeployContracts)?
    ).map_err(|_| Error::FailedToDeployContracts)?;

    // results.1.push(Event::DeployedChainContracts { 
    //     gateway_address: instantiate2_addr
    // });

    Ok(results)
}

pub fn deploy_chain(
    deps: DepsMut,
    info: MessageInfo,
    chain_name: ChainName,
    gateway_code_id: u64,
    gateway_instantiate_msg: GatewayInstantiateMsg,
    verifier_code_id: u64,
    verifier_instantiate_msg: VerifierInstantiateMsg,
    prover_code_id: u64,
    prover_instantiate_msg: ProverInstantiateMsg,
) -> error_stack::Result<Response, Error> {
    let mut response = Response::new();

    // Gateway
    let (msgs, events) = launch_contract(
        &deps, 
        &info, 
        Binary::new(instantiate2_salt(&info)), 
        gateway_code_id,
        cosmwasm_std::to_json_binary(&gateway_instantiate_msg)
        .change_context(Error::FailedToDeployContracts)?,
        "Gateway1.0.0".to_string(),
    )?;

    response = response.add_messages(msgs).add_events(events);

    Ok(response)
}
