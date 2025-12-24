use std::collections::{HashMap, HashSet};

use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, Response, Storage, WasmMsg};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::contract::errors::Error;
use crate::contract::query::instantiate2_addr;
use crate::events::{ContractInstantiation, Event};
use crate::msg::{DeploymentParams, ProverMsg, VerifierMsg};
use crate::state;
use crate::state::{ChainContracts, ProtocolContracts};

pub fn register_protocol(
    deps: DepsMut,
    service_registry: Addr,
    router: Addr,
    multisig: Addr,
) -> Result<Response, Error> {
    let protocol = ProtocolContracts {
        service_registry,
        router,
        multisig,
    };
    state::save_protocol_contracts(deps.storage, &protocol)
        .change_context(Error::UnableToPersistProtocol)?;
    Ok(Response::default())
}

pub fn register_chain(
    storage: &mut dyn Storage,
    chain_name: ChainName,
    prover_addr: Addr,
    gateway_addr: Addr,
    voting_verifier_address: Addr,
) -> Result<Response, Error> {
    state::save_chain_contracts(
        storage,
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
    sender: Addr,
    verifiers: HashSet<Addr>,
) -> Result<Response, Error> {
    state::update_verifier_set_for_prover(deps.storage, sender, verifiers)
        .change_context(Error::VerifierSetActivationFailed)?;
    Ok(Response::new())
}

fn launch_contract(
    deps: &Deps,
    env: &Env,
    salt: Binary,
    code_id: u64,
    instantiate_msg: Binary,
    label: String,
    admin: String,
) -> Result<(WasmMsg, Addr), Error> {
    Ok((
        WasmMsg::Instantiate2 {
            admin: Some(admin),
            code_id,
            msg: instantiate_msg,
            funds: vec![],
            label,
            salt: salt.clone(),
        },
        instantiate2_addr(deps, env, code_id, salt.as_slice())
            .change_context(Error::Instantiate2Address)?,
    ))
}

fn instantiate_gateway(
    ctx: &InstantiateContext,
    label: String,
    router_address: Addr,
    verifier_address: Addr,
) -> Result<(WasmMsg, Addr), Error> {
    launch_contract(
        &ctx.deps.as_ref(),
        &ctx.env,
        ctx.salt.clone(),
        ctx.gateway_code_id,
        cosmwasm_std::to_json_binary(&gateway_api::msg::InstantiateMsg {
            verifier_address: verifier_address.to_string().clone(),
            router_address: router_address.to_string().clone(),
        })
        .change_context(Error::InstantiateGateway)?,
        label,
        ctx.gateway_contract_admin.clone(),
    )
}

fn instantiate_verifier(
    ctx: &InstantiateContext,
    label: String,
    service_registry_address: Addr,
    verifier_msg: &VerifierMsg,
) -> Result<(WasmMsg, Addr), Error> {
    launch_contract(
        &ctx.deps.as_ref(),
        &ctx.env,
        ctx.salt.clone(),
        ctx.verifier_code_id,
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
            chain_codec_address: verifier_msg.chain_codec_address.clone(),
        })
        .change_context(Error::InstantiateVerifier)?,
        label,
        ctx.verifier_contract_admin.clone(),
    )
}

fn instantiate_prover(
    ctx: &InstantiateContext,
    label: String,
    gateway_address: Addr,
    service_registry_address: Addr,
    multisig_address: Addr,
    verifier_address: Addr,
    prover_msg: &ProverMsg,
) -> Result<(WasmMsg, Addr), Error> {
    launch_contract(
        &ctx.deps.as_ref(),
        &ctx.env,
        ctx.salt.clone(),
        ctx.prover_code_id,
        cosmwasm_std::to_json_binary(&solana_multisig_prover_api::msg::InstantiateMsg {
            admin_address: prover_msg.admin_address.to_string(),
            governance_address: prover_msg.governance_address.to_string(),
            coordinator_address: ctx.env.contract.address.to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            voting_verifier_address: verifier_address.to_string(),
            signing_threshold: prover_msg.signing_threshold,
            service_name: prover_msg.service_name.to_string(),
            chain_name: prover_msg.chain_name.to_string(),
            verifier_set_diff_threshold: prover_msg.verifier_set_diff_threshold,
            key_type: prover_msg.key_type,
            domain_separator: prover_msg.domain_separator,
            chain_codec_address: prover_msg.chain_codec_address.to_string(),
            sig_verifier_address: prover_msg.sig_verifier_address.clone(),
            notify_signing_session: prover_msg.notify_signing_session,
            expect_full_message_payloads: prover_msg.expect_full_message_payloads,
        })
        .change_context(Error::InstantiateProver)?,
        label,
        ctx.prover_contract_admin.clone(),
    )
}

struct InstantiateContext<'a> {
    deps: DepsMut<'a>,
    env: Env,
    salt: Binary,
    gateway_code_id: u64,
    gateway_contract_admin: String,
    verifier_code_id: u64,
    verifier_contract_admin: String,
    prover_code_id: u64,
    prover_contract_admin: String,
}

pub fn instantiate_chain_contracts(
    deps: DepsMut,
    env: Env,
    deployment_name: nonempty::String,
    salt: Binary,
    params: DeploymentParams,
) -> Result<Response, Error> {
    let mut response = Response::new();
    state::validate_deployment_name_availability(deps.storage, deployment_name.clone())
        .change_context(Error::InstantiateContracts)?;

    let protocol =
        state::protocol_contracts(deps.storage).change_context(Error::ProtocolNotRegistered)?;

    match params {
        DeploymentParams::Manual(params) => {
            let verifier_address =
                instantiate2_addr(&deps.as_ref(), &env, params.verifier.code_id, salt.as_ref())
                    .change_context(Error::Instantiate2Address)?;

            let gateway_contract_admin = deps
                .api
                .addr_validate(params.gateway.contract_admin.as_str())
                .map_err(|_| Error::InvalidAddress(params.gateway.contract_admin.to_string()))?
                .to_string();

            let verifier_contract_admin = deps
                .api
                .addr_validate(params.verifier.contract_admin.as_str())
                .map_err(|_| Error::InvalidAddress(params.verifier.contract_admin.to_string()))?
                .to_string();

            let prover_contract_admin = deps
                .api
                .addr_validate(params.prover.contract_admin.as_str())
                .map_err(|_| Error::InvalidAddress(params.prover.contract_admin.to_string()))?
                .to_string();

            let ctx = InstantiateContext {
                deps,
                env,
                salt,
                gateway_code_id: params.gateway.code_id,
                gateway_contract_admin,
                verifier_code_id: params.verifier.code_id,
                verifier_contract_admin,
                prover_code_id: params.prover.code_id,
                prover_contract_admin,
            };

            let (msg, gateway_address) = instantiate_gateway(
                &ctx,
                params.gateway.label.clone(),
                protocol.router.clone(),
                verifier_address.clone(),
            )
            .change_context(Error::InstantiateContracts)?;

            response = response.add_message(msg);

            let (msg, voting_verifier_address) = instantiate_verifier(
                &ctx,
                params.verifier.label.clone(),
                protocol.service_registry.clone(),
                &params.verifier.msg,
            )?;

            response = response.add_message(msg);

            let (msg, multisig_prover_address) = instantiate_prover(
                &ctx,
                params.prover.label.clone(),
                gateway_address.clone(),
                protocol.service_registry.clone(),
                protocol.multisig.clone(),
                voting_verifier_address.clone(),
                &params.prover.msg,
            )?;

            response = response
                .add_message(msg)
                .add_event(Event::ContractsInstantiated {
                    gateway: ContractInstantiation {
                        address: gateway_address.clone(),
                        code_id: params.gateway.code_id,
                    },
                    voting_verifier: ContractInstantiation {
                        address: verifier_address,
                        code_id: params.verifier.code_id,
                    },
                    multisig_prover: ContractInstantiation {
                        address: multisig_prover_address.clone(),
                        code_id: params.prover.code_id,
                    },
                    chain_name: params.prover.msg.chain_name.clone(),
                    deployment_name: deployment_name.clone(),
                });

            state::save_deployed_contracts(
                ctx.deps.storage,
                deployment_name,
                ChainContracts {
                    chain_name: params.prover.msg.chain_name,
                    msg_id_format: params.verifier.msg.msg_id_format,
                    gateway: gateway_address,
                    voting_verifier: voting_verifier_address,
                    multisig_prover: multisig_prover_address,
                },
            )
            .change_context(Error::InstantiateContracts)?;
        }
    }

    Ok(response)
}

pub fn register_deployment(
    deps: DepsMut,
    original_sender: Addr,
    deployment_name: nonempty::String,
) -> Result<Response, Error> {
    let deployed_contracts = state::deployment(deps.storage, deployment_name.clone())
        .change_context(Error::ChainContractsInfo)?;

    let protocol_contracts =
        state::protocol_contracts(deps.storage).change_context(Error::ProtocolNotRegistered)?;

    register_chain(
        deps.storage,
        deployed_contracts.chain_name.clone(),
        deployed_contracts.multisig_prover.clone(),
        deployed_contracts.gateway.clone(),
        deployed_contracts.voting_verifier,
    )?;

    let router: router_api::Client =
        client::ContractClient::new(deps.querier, &protocol_contracts.router).into();
    let multisig: multisig::Client =
        client::ContractClient::new(deps.querier, &protocol_contracts.multisig).into();

    Ok(Response::new()
        .add_message(router.register_chain(
            original_sender.clone(),
            deployed_contracts.chain_name.clone(),
            router_api::Address::from(deployed_contracts.gateway),
            deployed_contracts.msg_id_format,
        ))
        .add_message(multisig.authorize_callers_from_proxy(
            original_sender,
            HashMap::from([(
                deployed_contracts.multisig_prover.to_string(),
                deployed_contracts.chain_name,
            )]),
        )))
}
