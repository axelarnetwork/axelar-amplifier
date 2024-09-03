use axelar_wasm_std::VerificationStatus;
use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierResult, Uint128, WasmQuery};
use multisig::msg::Signer;
use multisig::multisig::Multisig;
use multisig::types::MultisigState;
use multisig::verifier_set::VerifierSet;
use service_registry::{
    AuthorizationState, BondingState, Verifier, WeightedVerifier, VERIFIER_WEIGHT,
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
    verifier_set_status: VerificationStatus,
) -> impl Fn(&WasmQuery) -> QuerierResult {
    move |wq: &WasmQuery| match wq {
        WasmQuery::Smart { contract_addr, .. } if contract_addr == GATEWAY_ADDRESS => {
            gateway_mock_querier_handler()
        }
        WasmQuery::Smart { contract_addr, msg } if contract_addr == MULTISIG_ADDRESS => {
            multisig_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, msg } if contract_addr == SERVICE_REGISTRY_ADDRESS => {
            service_registry_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, .. } if contract_addr == VOTING_VERIFIER_ADDRESS => {
            voting_verifier_mock_querier_handler(verifier_set_status)
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
        multisig::msg::QueryMsg::Multisig { session_id: _ } => {
            to_json_binary(&mock_multisig(operators))
        }
        multisig::msg::QueryMsg::PublicKey {
            verifier_address,
            key_type: _,
        } => to_json_binary(
            &operators
                .iter()
                .find(|op| op.address == verifier_address)
                .unwrap()
                .pub_key,
        ),
        _ => panic!("unexpected query: {:?}", msg),
    };

    Ok(result.into()).into()
}

fn mock_multisig(operators: Vec<TestOperator>) -> Multisig {
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

    let verifier_set = VerifierSet {
        signers,
        threshold: quorum,
        created_at: 1,
    };

    Multisig {
        state: MultisigState::Completed {
            completed_at: 12345,
        },
        verifier_set,
        signatures,
    }
}

fn service_registry_mock_querier_handler(
    msg: service_registry::msg::QueryMsg,
    operators: Vec<TestOperator>,
) -> QuerierResult {
    let result = match msg {
        service_registry::msg::QueryMsg::Service { service_name } => {
            to_json_binary(&service_registry::Service {
                name: service_name.to_string(),
                coordinator_contract: Addr::unchecked(COORDINATOR_ADDRESS),
                min_num_verifiers: 1,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::new(1).try_into().unwrap(),
                bond_denom: "uaxl".to_string(),
                unbonding_period_days: 1,
                description: "verifiers".to_string(),
            })
        }
        service_registry::msg::QueryMsg::ActiveVerifiers {
            service_name: _,
            chain_name: _,
        } => to_json_binary(
            &operators
                .clone()
                .into_iter()
                .map(|op| WeightedVerifier {
                    verifier_info: Verifier {
                        address: op.address,
                        bonding_state: BondingState::Bonded {
                            amount: op.weight.try_into().unwrap(),
                        },
                        authorization_state: AuthorizationState::Authorized,
                        service_name: SERVICE_NAME.to_string(),
                    },
                    weight: VERIFIER_WEIGHT,
                })
                .collect::<Vec<WeightedVerifier>>(),
        ),
        _ => panic!("unexpected query: {:?}", msg),
    };
    Ok(result.into()).into()
}

fn voting_verifier_mock_querier_handler(status: VerificationStatus) -> QuerierResult {
    Ok(to_json_binary(&status).into()).into()
}
