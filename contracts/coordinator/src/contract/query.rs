use std::collections::HashSet;

use cosmwasm_std::{to_json_binary, Addr, Deps, Order, QueryRequest, StdResult, WasmQuery};
use itertools::Itertools;
use service_registry_api::msg::QueryMsg::Verifier;
use service_registry_api::msg::VerifierDetails;

use crate::error::ContractError;
use crate::msg::VerifierInfo;
use crate::state::{CONFIG, VERIFIER_PROVER_INDEXED_MAP};

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> StdResult<bool> {
    Ok(!is_verifier_in_any_verifier_set(deps, &verifier_address))
}

pub fn verifier_details_with_provers(
    deps: Deps,
    service_name: String,
    verifier_address: Addr,
) -> Result<VerifierInfo, ContractError> {
    let config = CONFIG.load(deps.storage).expect("couldn't load config");

    let verifier_details: VerifierDetails = deps
        .querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.service_registry.to_string(),
            msg: to_json_binary(&Verifier {
                service_name,
                verifier: verifier_address.to_string(),
            })
            .map_err(ContractError::from)?,
        }))
        .map_err(ContractError::from)?;

    let active_prover_set = get_provers_for_verifier(deps, verifier_address)?;

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

fn get_provers_for_verifier(
    deps: Deps,
    verifier_address: Addr,
) -> Result<HashSet<Addr>, ContractError> {
    let provers = VERIFIER_PROVER_INDEXED_MAP
        .idx
        .by_verifier
        .prefix(verifier_address)
        .range(deps.storage, None, None, Order::Ascending)
        .map(|result| result.map(|(_, record)| record.prover))
        .try_collect()?;

    Ok(provers)
}
