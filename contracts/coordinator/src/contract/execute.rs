use std::collections::HashSet;

use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, WasmMsg, WasmQuery};
use error_stack::{report, Result, ResultExt};
use router_api::ChainName;

use crate::events::ContractInstantiated;
use crate::msg::{DeploymentParams, ProverMsg, VerifierMsg};
use crate::state::{
    load_config, save_chain_contracts, save_prover_for_chain, update_verifier_set_for_prover,
    ChainContracts, DEPLOYED_CHAINS, INSTANTIATE2_COUNTER,
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to activate verifier set")]
    VerifierSetActivationFailed,

    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),

    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),

    #[error("failed to generate instantiate2 salt")]
    Instantiate2Salt,

    #[error("failed to generate instantiate2 address")]
    Instantiate2Address,

    #[error("failed to instantiate core contracts")]
    InstantiateContracts,

    #[error("failed to query code info for code id {0}")]
    QueryCodeInfo(u64),

    #[error("failed to query contract state")]
    QueryState,

    #[error("deplyment name {0} is in use")]
    DeploymentName(String),

    #[error("failed to instantiate gateway")]
    InstantiateGateway,

    #[error("failed to instantiate verifier")]
    InstantiateVerifier,

    #[error("failed to instantiate prover")]
    InstantiateProver,
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

fn instantiate2_salt(deps: &mut DepsMut) -> error_stack::Result<Vec<u8>, Error> {
    let counter_value = INSTANTIATE2_COUNTER
        .cur(deps.storage)
        .to_be_bytes()
        .to_vec();

    INSTANTIATE2_COUNTER
        .incr(deps.storage)
        .change_context(Error::Instantiate2Salt)?;

    Ok(counter_value)
}

fn instantiate2_addr(
    deps: &DepsMut,
    env: &Env,
    code_id: u64,
    salt: &[u8],
) -> error_stack::Result<Addr, Error> {
    let code_info: cosmwasm_std::CodeInfoResponse = deps
        .querier
        .query(&WasmQuery::CodeInfo { code_id }.into())
        .change_context(Error::QueryCodeInfo(code_id))?;

    deps.api
        .addr_humanize(
            &cosmwasm_std::instantiate2_address(
                code_info.checksum.as_slice(),
                &deps
                    .api
                    .addr_canonicalize(&env.contract.address.to_string().clone())
                    .change_context(Error::Instantiate2Address)?,
                salt,
            )
            .change_context(Error::Instantiate2Address)?,
        )
        .change_context(Error::Instantiate2Address)
}

fn deployment_name_is_free(deps: &Deps, deployment_name: &str) -> error_stack::Result<(), Error> {
    let deployments = DEPLOYED_CHAINS
        .may_load(deps.storage, deployment_name.to_string())
        .change_context(Error::QueryState)?;

    if let Some(_) = deployments {
        error_stack::Result::Err(report!(Error::DeploymentName(deployment_name.to_string())))
    } else {
        Ok(())
    }
}

fn launch_contract(
    deps: &DepsMut,
    info: &MessageInfo,
    env: &Env,
    salt: Binary,
    code_id: u64,
    instantiate_msg: Binary,
    label: String,
) -> error_stack::Result<(WasmMsg, Addr), Error> {
    Ok((
        WasmMsg::Instantiate2 {
            admin: Some(info.sender.to_string()),
            code_id,
            msg: instantiate_msg,
            funds: info.funds.clone(),
            label,
            salt: salt.clone(),
        },
        instantiate2_addr(deps, env, code_id, salt.as_slice())?,
    ))
}

fn instantiate_gateway(
    deps: &DepsMut,
    info: &MessageInfo,
    env: &Env,
    salt: Binary,
    code_id: u64,
    label: String,
    router_address: Addr,
    verifier_address: Addr,
) -> error_stack::Result<(WasmMsg, Addr), Error> {
    launch_contract(
        deps,
        info,
        env,
        salt,
        code_id,
        cosmwasm_std::to_json_binary(&gateway_api::msg::InstantiateMsg {
            verifier_address: verifier_address.to_string().clone(),
            router_address: router_address.to_string().clone(),
        })
        .change_context(Error::InstantiateGateway)?,
        label,
    )
}

fn instantiate_verifier(
    deps: &DepsMut,
    info: &MessageInfo,
    env: &Env,
    salt: Binary,
    code_id: u64,
    label: String,
    service_registry_address: Addr,
    verifier_msg: &VerifierMsg,
) -> error_stack::Result<(WasmMsg, Addr), Error> {
    launch_contract(
        deps,
        info,
        env,
        salt,
        code_id,
        cosmwasm_std::to_json_binary(&voting_verifier_api::msg::InstantiateMsg {
            governance_address: verifier_msg.governance_address.clone(),
            service_registry_address: axelar_wasm_std::nonempty::String::try_from(
                service_registry_address.into_string(),
            )
            .change_context(Error::InstantiateVerifier)?,
            service_name: verifier_msg.service_name.clone(),
            source_gateway_address: verifier_msg.source_gateway_address.clone(),
            voting_threshold: verifier_msg.voting_threshold,
            block_expiry: verifier_msg.block_expiry,
            confirmation_height: verifier_msg.confirmation_height,
            source_chain: verifier_msg.source_chain.clone(),
            rewards_address: verifier_msg.rewards_address.clone(),
            msg_id_format: verifier_msg.msg_id_format.clone(),
            address_format: verifier_msg.address_format.clone(),
        })
        .change_context(Error::InstantiateVerifier)?,
        label,
    )
}

fn instantiate_prover(
    deps: &DepsMut,
    info: &MessageInfo,
    env: &Env,
    salt: Binary,
    code_id: u64,
    label: String,
    gateway_address: Addr,
    service_registry_address: Addr,
    multisig_address: Addr,
    verifier_address: Addr,
    prover_msg: &ProverMsg,
) -> error_stack::Result<(WasmMsg, Addr), Error> {
    launch_contract(
        deps,
        info,
        env,
        salt,
        code_id,
        cosmwasm_std::to_json_binary(&multisig_prover_api::msg::InstantiateMsg {
            admin_address: info.sender.to_string().clone(),
            governance_address: prover_msg.governance_address.to_string().clone(),
            coordinator_address: env.contract.address.to_string().clone(),
            gateway_address: gateway_address.to_string().clone(),
            multisig_address: multisig_address.to_string().clone(),
            service_registry_address: service_registry_address.to_string().clone(),
            voting_verifier_address: verifier_address.to_string().clone(),
            signing_threshold: prover_msg.signing_threshold,
            service_name: prover_msg.service_name.to_string(),
            chain_name: prover_msg.chain_name.clone(),
            verifier_set_diff_threshold: prover_msg.verifier_set_diff_threshold,
            encoder: prover_msg.encoder,
            key_type: prover_msg.key_type,
            domain_separator: prover_msg.domain_separator,
        })
        .change_context(Error::InstantiateProver)?,
        label,
    )
}

pub fn instantiate_chain_contracts(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    deployment_name: String,
    params: &DeploymentParams,
) -> error_stack::Result<Response, Error> {
    let mut response = Response::new();
    deployment_name_is_free(&deps.as_ref(), &deployment_name)
        .change_context(Error::InstantiateContracts)?;

    let config = load_config(deps.storage);

    let gateway_salt = instantiate2_salt(&mut deps).change_context(Error::InstantiateContracts)?;

    let verifier_salt = instantiate2_salt(&mut deps).change_context(Error::InstantiateContracts)?;

    let prover_salt = instantiate2_salt(&mut deps).change_context(Error::InstantiateContracts)?;

    let chain_contracts: Option<ChainContracts>;

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
            let (msg, gateway_address) = instantiate_gateway(
                &deps,
                &info,
                &env,
                Binary::new(gateway_salt),
                *gateway_code_id,
                gateway_label.clone(),
                config.router.clone(),
                instantiate2_addr(&deps, &env, *verifier_code_id, verifier_salt.as_ref())
                    .change_context(Error::InstantiateContracts)?,
            )
            .change_context(Error::InstantiateContracts)?;

            response = response
                .add_message(msg)
                .add_event(ContractInstantiated::Gateway {
                    address: gateway_address.clone(),
                    code_id: *gateway_code_id,
                });

            let (msg, voting_verifier_address) = instantiate_verifier(
                &deps,
                &info,
                &env,
                Binary::new(verifier_salt),
                *verifier_code_id,
                verifier_label.clone(),
                config.service_registry.clone(),
                verifier_msg,
            )?;

            response = response
                .add_message(msg)
                .add_event(ContractInstantiated::VotingVerifier {
                    address: voting_verifier_address.clone(),
                    code_id: *verifier_code_id,
                });

            let (msg, multisig_prover_address) = instantiate_prover(
                &deps,
                &info,
                &env,
                Binary::new(prover_salt),
                *prover_code_id,
                prover_label.clone(),
                gateway_address.clone(),
                config.service_registry.clone(),
                config.multisig.clone(),
                voting_verifier_address.clone(),
                prover_msg,
            )?;

            chain_contracts = Some(ChainContracts {
                gateway: gateway_address,
                voting_verifier: voting_verifier_address,
                multisig_prover: multisig_prover_address.clone(),
            });

            response = response
                .add_message(msg)
                .add_event(ContractInstantiated::MultisigProver {
                    address: multisig_prover_address.clone(),
                    code_id: *prover_code_id,
                });
        }
    }

    if let Some(c) = chain_contracts {
        DEPLOYED_CHAINS
            .save(deps.storage, deployment_name.to_string(), &c)
            .change_context(Error::InstantiateContracts)?;
    }

    Ok(response)
}
