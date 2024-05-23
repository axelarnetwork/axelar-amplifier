use axelar_wasm_std::VerificationStatus;
use cosmwasm_std::{from_json, to_json_binary, QuerierResult, WasmQuery};
use multisig::{msg::Signer, multisig::Multisig, types::MultisigState, verifier_set::VerifierSet};
use service_registry::state::{
    AuthorizationState, BondingState, WeightedWorker, Worker, WORKER_WEIGHT,
};

use super::test_data::{self, TestOperator};

pub const GATEWAY_ADDRESS: &str = "gateway";
pub const MULTISIG_ADDRESS: &str = "multisig";
pub const COORDINATOR_ADDRESS: &str = "coordinator";
pub const SERVICE_REGISTRY_ADDRESS: &str = "service_registry";
pub const VOTING_VERIFIER_ADDRESS: &str = "voting_verifier";
pub const ADMIN: &str = "admin";
pub const GOVERNANCE: &str = "governance";
pub const SERVICE_NAME: &str = "validators";

pub fn mock_querier_handler(
    operators: Vec<TestOperator>,
    worker_set_status: VerificationStatus,
) -> impl Fn(&WasmQuery) -> QuerierResult {
    move |wq: &WasmQuery| match wq {
        WasmQuery::Smart { contract_addr, .. } if contract_addr == GATEWAY_ADDRESS => {
            gateway_mock_querier_handler()
        }
        WasmQuery::Smart { contract_addr, msg } if contract_addr == MULTISIG_ADDRESS => {
            multisig_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, .. } if contract_addr == SERVICE_REGISTRY_ADDRESS => {
            service_registry_mock_querier_handler(operators.clone())
        }
        WasmQuery::Smart { contract_addr, .. } if contract_addr == VOTING_VERIFIER_ADDRESS => {
            voting_verifier_mock_querier_handler(worker_set_status)
        }
        _ => panic!("unexpected query: {:?}", wq),
    }
}

fn gateway_mock_querier_handler() -> QuerierResult {
    Ok(to_json_binary(&test_data::messages()).into()).into()
}

fn multisig_mock_querier_handler(
    msg: multisig::msg::QueryMsg,
    operators: Vec<TestOperator>,
) -> QuerierResult {
    let result = match msg {
        multisig::msg::QueryMsg::GetMultisig { session_id: _ } => {
            to_json_binary(&mock_get_multisig(operators))
        }
        multisig::msg::QueryMsg::GetPublicKey {
            verifier_address: worker_address,
            key_type: _,
        } => to_json_binary(
            &operators
                .iter()
                .find(|op| op.address == worker_address)
                .unwrap()
                .pub_key,
        ),
        _ => panic!("unexpected query: {:?}", msg),
    };

    Ok(result.into()).into()
}

fn mock_get_multisig(operators: Vec<TestOperator>) -> Multisig {
    let quorum = test_data::quorum();

    let signers = operators
        .clone()
        .into_iter()
        .map(|op| {
            (
                op.address.as_str().into(),
                Signer {
                    address: op.address,
                    weight: op.weight,
                    pub_key: op.pub_key,
                },
            )
        })
        .collect();

    let signatures = operators
        .into_iter()
        .filter_map(|op| {
            if let Some(signature) = op.signature {
                Some((op.address.into_string(), signature))
            } else {
                None
            }
        })
        .collect();

    let worker_set = VerifierSet {
        signers,
        threshold: quorum,
        created_at: 1,
    };

    Multisig {
        state: MultisigState::Completed {
            completed_at: 12345,
        },
        verifier_set: worker_set,
        signatures,
    }
}

fn service_registry_mock_querier_handler(operators: Vec<TestOperator>) -> QuerierResult {
    Ok(to_json_binary(
        &operators
            .clone()
            .into_iter()
            .map(|op| WeightedWorker {
                worker_info: Worker {
                    address: op.address,
                    bonding_state: BondingState::Bonded { amount: op.weight },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: SERVICE_NAME.to_string(),
                },
                weight: WORKER_WEIGHT,
            })
            .collect::<Vec<WeightedWorker>>(),
    )
    .into())
    .into()
}

fn voting_verifier_mock_querier_handler(status: VerificationStatus) -> QuerierResult {
    Ok(to_json_binary(&status).into()).into()
}
