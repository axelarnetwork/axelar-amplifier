use std::collections::HashSet;

use cosmwasm_std::{Addr, Deps, Order, StdError};
use error_stack::{Result, ResultExt};
use itertools::Itertools;
use service_registry_api::msg::VerifierDetails;

use crate::msg::{ChainContractsKey, ChainContractsResponse, VerifierInfo};
use crate::state::{
    contracts_by_chain, contracts_by_gateway, contracts_by_prover, contracts_by_verifier,
    load_config, VERIFIER_PROVER_INDEXED_MAP,
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error(
        "coordinator failed to retrieve verifier details and corresponding provers. service_name: {service_name}, verifier_address: {verifier_address}"
    )]
    VerifierDetailsWithProvers {
        service_name: String,
        verifier_address: String,
    },

    #[error("coordinator failed to retreive chain contracts info")]
    ChainContractsInfo,

    #[error("failed to get provers for verifier {0}")]
    FailedToGetProversForVerifier(Addr),
}

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> Result<bool, Error> {
    Ok(!is_verifier_in_any_verifier_set(deps, &verifier_address))
}

pub fn verifier_details_with_provers(
    deps: Deps,
    service_name: String,
    verifier_address: Addr,
) -> Result<VerifierInfo, Error> {
    let config = load_config(deps.storage);

    let service_registry: service_registry_api::Client =
        client::ContractClient::new(deps.querier, &config.service_registry).into();

    let verifier_details: VerifierDetails = service_registry
        .verifier(service_name.clone(), verifier_address.to_string())
        .change_context(Error::VerifierDetailsWithProvers {
            service_name: service_name.clone(),
            verifier_address: verifier_address.to_string(),
        })?;

    let active_prover_set = get_provers_for_verifier(deps, verifier_address.clone())
        .change_context(Error::VerifierDetailsWithProvers {
            service_name: service_name.clone(),
            verifier_address: verifier_address.to_string(),
        })?;

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

fn get_provers_for_verifier(deps: Deps, verifier_address: Addr) -> Result<HashSet<Addr>, Error> {
    VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .map(|result| result.map(|(_, record)| record.prover))
        .try_collect::<Addr, HashSet<Addr>, StdError>()
        .change_context(Error::FailedToGetProversForVerifier(
            verifier_address.clone(),
        ))
}

pub fn get_chain_contracts_info(
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
