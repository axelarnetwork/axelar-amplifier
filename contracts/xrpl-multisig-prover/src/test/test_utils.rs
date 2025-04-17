use axelar_wasm_std::VerificationStatus;
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{from_json, to_json_binary, QuerierResult, Uint128, WasmQuery};
use interchain_token_service::TokenId;
use multisig::msg::Signer;
use multisig::multisig::Multisig;
use multisig::types::MultisigState;
use multisig::verifier_set::VerifierSet;
use router_api::Message;
use service_registry::VERIFIER_WEIGHT;
use service_registry_api::{AuthorizationState, BondingState, Verifier, WeightedVerifier};
use xrpl_voting_verifier::msg::MessageStatus;

use super::test_data::{self, TestOperator};

pub const CHAIN_NAME: &str = "xrpl";
pub const GATEWAY_ADDRESS: &str = "gateway";
pub const MULTISIG_ADDRESS: &str = "multisig";
pub const COORDINATOR_ADDRESS: &str = "coordinator";
pub const SERVICE_REGISTRY_ADDRESS: &str = "service_registry";
pub const VOTING_VERIFIER_ADDRESS: &str = "voting_verifier";
pub const ADMIN: &str = "admin";
pub const GOVERNANCE: &str = "governance";
pub const SERVICE_NAME: &str = "validators";
pub const XRPL_MULITISIG_ADDRESS: &str = "rNrjh1KGZk2jBR3wPfAQnoidtFFYQKbQn2";
pub const XRP_TOKEN_ID: [u8; 32] = [
    186, 90, 33, 202, 136, 239, 107, 186, 43, 255, 245, 8, 137, 148, 249, 14, 16, 119, 226, 161,
    204, 61, 204, 56, 189, 38, 31, 0, 252, 226, 130, 79,
];

pub fn mock_querier_handler(
    operators: Vec<TestOperator>,
    verifier_set_status: VerificationStatus,
) -> impl Fn(&WasmQuery) -> QuerierResult {
    move |wq: &WasmQuery| match wq {
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr == MockApi::default().addr_make(GATEWAY_ADDRESS).as_str() =>
        {
            gateway_mock_querier_handler(from_json(msg).unwrap())
        }
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr == MockApi::default().addr_make(MULTISIG_ADDRESS).as_str() =>
        {
            multisig_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr
                == MockApi::default()
                    .addr_make(SERVICE_REGISTRY_ADDRESS)
                    .as_str() =>
        {
            service_registry_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr
                == MockApi::default()
                    .addr_make(VOTING_VERIFIER_ADDRESS)
                    .as_str() =>
        {
            voting_verifier_mock_querier_handler(from_json(msg).unwrap(), verifier_set_status)
        }
        _ => panic!("unexpected query: {:?}", wq),
    }
}

fn gateway_mock_querier_handler(msg: xrpl_gateway::msg::QueryMsg) -> QuerierResult {
    match msg {
        xrpl_gateway::msg::QueryMsg::OutgoingMessages(_cc_ids) => {
            let messages = test_data::outgoing_messages()
                .iter()
                .map(|(msg, _payload)| msg.clone())
                .collect::<Vec<Message>>();
            Ok(to_json_binary(&messages).into()).into()
        }
        xrpl_gateway::msg::QueryMsg::XrpTokenId => {
            Ok(to_json_binary(&TokenId::new(XRP_TOKEN_ID)).into()).into()
        }
        _ => panic!("unexpected query: {:?}", msg),
    }
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
                .find(|op| op.address.as_str() == verifier_address)
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
    msg: service_registry_api::msg::QueryMsg,
    operators: Vec<TestOperator>,
) -> QuerierResult {
    let result = match msg {
        service_registry_api::msg::QueryMsg::Service { service_name } => {
            to_json_binary(&service_registry_api::Service {
                name: service_name.to_string(),
                coordinator_contract: MockApi::default().addr_make(COORDINATOR_ADDRESS),
                min_num_verifiers: 1,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::new(1).try_into().unwrap(),
                bond_denom: "uaxl".to_string(),
                unbonding_period_days: 1,
                description: "verifiers".to_string(),
            })
        }
        service_registry_api::msg::QueryMsg::ActiveVerifiers {
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

fn voting_verifier_mock_querier_handler(
    msg: xrpl_voting_verifier::msg::QueryMsg,
    status: VerificationStatus,
) -> QuerierResult {
    match msg {
        xrpl_voting_verifier::msg::QueryMsg::MessagesStatus(messages) => {
            let messages_status = messages
                .iter()
                .map(|message| MessageStatus {
                    status,
                    message: message.clone(),
                })
                .collect::<Vec<MessageStatus>>();
            Ok(to_json_binary(&messages_status).into()).into()
        }
        _ => panic!("unexpected query: {:?}", msg),
    }
}
