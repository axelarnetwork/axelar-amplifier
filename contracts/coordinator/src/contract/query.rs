use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Deps, Order, StdError};
use error_stack::{Result, ResultExt};
use itertools::Itertools;
use service_registry_api::msg::VerifierDetails;

use crate::contract::errors::Error;
use crate::msg::{ChainContractsKey, ChainContractsResponse, VerifierInfo};
use crate::state;
use crate::state::{
    contracts_by_chain, contracts_by_gateway, contracts_by_prover, contracts_by_verifier,
    VERIFIER_PROVER_INDEXED_MAP,
};

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> Result<bool, Error> {
    Ok(!is_verifier_in_any_verifier_set(deps, &verifier_address))
}

pub fn verifier_details_with_provers(
    deps: Deps,
    service_name: String,
    verifier_address: Addr,
) -> Result<VerifierInfo, Error> {
    let protocol =
        state::protocol_contracts(deps.storage).change_context(Error::ProtocolNotRegistered)?;

    let service_registry: service_registry_api::Client =
        client::ContractClient::new(deps.querier, &protocol.service_registry).into();

    let verifier_details: VerifierDetails = service_registry
        .verifier(service_name.clone(), verifier_address.to_string())
        .change_context(Error::VerifierDetailsWithProvers {
            service_name: service_name.clone(),
            verifier_address: verifier_address.to_string(),
        })?;

    let mut active_prover_set = provers_for_verifier(deps, verifier_address.clone())
        .change_context(Error::VerifierDetailsWithProvers {
            service_name: service_name.clone(),
            verifier_address: verifier_address.to_string(),
        })?;

    active_prover_set.sort();

    Ok(VerifierInfo {
        verifier: verifier_details.verifier,
        weight: verifier_details.weight,
        supported_chains: verifier_details.supported_chains,
        actively_signing_for: active_prover_set,
    })
}

fn is_verifier_in_any_verifier_set(deps: Deps, verifier_address: &Addr) -> bool {
    VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .any(|_| true)
}

fn provers_for_verifier(
    deps: Deps,
    verifier_address: Addr,
) -> core::result::Result<Vec<Addr>, StdError> {
    VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .map(|result| result.map(|(_, record)| record.prover))
        .dedup()
        .try_collect()
}

pub fn chain_contracts_info(
    deps: Deps,
    chain_contracts_key: ChainContractsKey,
) -> Result<ChainContractsResponse, Error> {
    match chain_contracts_key {
        ChainContractsKey::ChainName(chain_name) => contracts_by_chain(deps.storage, chain_name),

        ChainContractsKey::ProverAddress(prover_addr) => {
            contracts_by_prover(deps.storage, prover_addr)
        }

        ChainContractsKey::GatewayAddress(gateway_addr) => {
            contracts_by_gateway(deps.storage, gateway_addr)
        }

        ChainContractsKey::VerifierAddress(verifier_addr) => {
            contracts_by_verifier(deps.storage, verifier_addr)
        }
    }
    .change_context(Error::ChainContractsInfo)
    .map(ChainContractsResponse::from)
}

pub fn deployments(
    deps: Deps,
    start_after: Option<nonempty::String>,
    limit: nonempty::Usize,
) -> Result<Vec<ChainContractsResponse>, Error> {
    Ok(state::deployments(deps.storage, start_after, limit)
        .change_context(Error::ChainContractsInfo)?
        .map(|chains| ChainContractsResponse {
            chain_name: chains.chain_name,
            prover_address: chains.multisig_prover,
            verifier_address: chains.voting_verifier,
            gateway_address: chains.gateway,
        })
        .collect::<Vec<ChainContractsResponse>>())
}

pub fn deployment(
    deps: Deps,
    deployment_name: nonempty::String,
) -> Result<ChainContractsResponse, Error> {
    state::deployment(deps.storage, deployment_name.clone())
        .map(|chains| ChainContractsResponse {
            chain_name: chains.chain_name,
            prover_address: chains.multisig_prover,
            verifier_address: chains.voting_verifier,
            gateway_address: chains.gateway,
        })
        .change_context(Error::DeploymentNotFound(deployment_name))
}
