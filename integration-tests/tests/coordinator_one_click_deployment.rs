use std::collections::HashMap;
use std::str::FromStr;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, nonempty_str, Threshold, VerificationStatus};
use coordinator::events::ContractInstantiation;
use coordinator::msg::{
    ContractDeploymentInfo, DeploymentParams, ManualDeploymentParams, ProverMsg, VerifierMsg,
};
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{Binary, HexBinary};
use cw_multi_test::AppResponse;
use error_stack::Report;
use events::try_from;
use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::protocol::Protocol;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::KeyType;
use multisig_prover_api::encoding::Encoder;
use router_api::{Address, ChainName, CrossChainId, Message};
use serde::de::{DeserializeOwned, Error};
use serde::{Deserialize, Deserializer};

use crate::test_utils::Chain;

pub mod test_utils;

struct DeployedContracts {
    gateway: GatewayContract,
    voting_verifier: VotingVerifierContract,
    multisig_prover: MultisigProverContract,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-contracts_instantiated")]
struct ContractsInstantiated {
    #[serde(deserialize_with = "deserialize_json_attribute")]
    gateway: ContractInstantiation,
    #[serde(deserialize_with = "deserialize_json_attribute")]
    voting_verifier: ContractInstantiation,
    #[serde(deserialize_with = "deserialize_json_attribute")]
    multisig_prover: ContractInstantiation,
    #[serde(rename = "chain_name")]
    _chain_name: ChainName,
    #[serde(rename = "deployment_name")]
    _deployment_name: nonempty::String,
}

fn deserialize_json_attribute<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let json: String = Deserialize::deserialize(deserializer)?;
    serde_json::from_str::<T>(&json).map_err(D::Error::custom)
}

fn deploy_chains(
    protocol: &mut Protocol,
    chain_name: &str,
    chain: &Chain,
    deployment_name: nonempty::String,
    salt: Binary,
    register_with_router: bool,
) -> Result<AppResponse, Report<ContractError>> {
    // Deploy gateway, verifier and prover using InstantiateChainContracts

    let res = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::InstantiateChainContracts {
            deployment_name,
            salt,
            params: Box::new(DeploymentParams::Manual(ManualDeploymentParams {
                gateway: ContractDeploymentInfo {
                    code_id: chain.gateway.code_id,
                    label: "Gateway1.0.0".to_string(),
                    msg: (),
                },
                verifier: ContractDeploymentInfo {
                    code_id: chain.voting_verifier.code_id,
                    label: "Verifier1.0.0".to_string(),
                    msg: VerifierMsg {
                        governance_address: nonempty::String::try_from(
                            protocol.governance_address.to_string(),
                        )
                        .unwrap(),
                        service_name: protocol.service_name.clone(),
                        source_gateway_address: nonempty::String::try_from(
                            "0x4F4495243837681061C4743b74B3eEdf548D56A5".to_string(),
                        )
                        .unwrap(),
                        voting_threshold: Threshold::try_from((3, 4)).unwrap().try_into().unwrap(),
                        block_expiry: 10.try_into().unwrap(),
                        confirmation_height: 5,
                        source_chain: chain_name.parse().unwrap(),
                        rewards_address: protocol
                            .rewards
                            .contract_addr
                            .to_string()
                            .try_into()
                            .unwrap(),
                        msg_id_format:
                            axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                        address_format: axelar_wasm_std::address::AddressFormat::Eip55,
                    },
                },
                prover: ContractDeploymentInfo {
                    code_id: chain.multisig_prover.code_id,
                    label: "Prover1.0.0".to_string(),
                    msg: ProverMsg {
                        governance_address: protocol.governance_address.to_string(),
                        multisig_address: protocol.multisig.contract_addr.to_string(),
                        signing_threshold: Threshold::try_from((2u64, 3u64))
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        service_name: protocol.service_name.parse().unwrap(),
                        chain_name: chain_name.parse().unwrap(),
                        verifier_set_diff_threshold: 0,
                        encoder: Encoder::Abi,
                        key_type: KeyType::Ecdsa,
                        domain_separator: [0; 32],
                    },
                },
            })),
        },
    )?;

    // Gather each contract's address from the returned events
    let contracts = gather_contracts(protocol, res.clone());

    let response = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::RegisterProverContract {
            chain_name: chain_name.parse().unwrap(),
            new_prover_addr: contracts
                .multisig_prover
                .contract_addr
                .to_string()
                .trim_matches(|c| c == '"' || c == '/')
                .parse()
                .unwrap(),
        },
    );
    assert!(response.is_ok());

    protocol.multisig.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCallers {
            contracts: HashMap::from([(
                contracts
                    .multisig_prover
                    .contract_addr
                    .to_string()
                    .trim_matches(|c| c == '"' || c == '/')
                    .parse()
                    .unwrap(),
                chain_name.parse().unwrap(),
            )]),
        },
    )?;

    if register_with_router {
        protocol.router.execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &router_api::msg::ExecuteMsg::RegisterChain {
                chain: chain_name.parse().unwrap(),
                gateway_address: Address::from_str(
                    contracts
                        .gateway
                        .contract_addr
                        .to_string()
                        .trim_matches(|c| c == '"' || c == '/'),
                )
                .unwrap(),
                msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
            },
        )?;
    }

    Ok(res)
}

fn gather_contracts(protocol: &Protocol, app_response: AppResponse) -> DeployedContracts {
    let mut gateway = GatewayContract::default();
    let mut voting_verifier = VotingVerifierContract::default();
    let mut multisig_prover = MultisigProverContract::default();

    let event = app_response
        .events
        .iter()
        .map(|e| events::Event::Abci {
            event_type: e.ty.clone(),
            attributes: e
                .attributes
                .iter()
                .map(|attribute| {
                    (
                        attribute.key.clone(),
                        serde_json::Value::String(attribute.value.clone()),
                    )
                })
                .collect(),
        })
        .find_map(|e| ContractsInstantiated::try_from(e).ok())
        .unwrap();

    gateway.code_id = event.gateway.code_id;
    gateway.contract_addr = event.gateway.address;
    voting_verifier.code_id = event.voting_verifier.code_id;
    voting_verifier.contract_addr = event.voting_verifier.address;
    multisig_prover.admin_addr = protocol.governance_address.clone();
    multisig_prover.code_id = event.multisig_prover.code_id;
    multisig_prover.contract_addr = event.multisig_prover.address;

    DeployedContracts {
        gateway,
        voting_verifier,
        multisig_prover,
    }
}

#[test]
fn coordinator_one_click_deploys_each_contract_using_correct_code_ids_and_bytecode() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let res = deploy_chains(
        &mut protocol,
        "testchain",
        &chain1,
        nonempty::String::try_from("testchaindeploy").unwrap(),
        Binary::new(vec![1]),
        true,
    );
    assert!(res.is_ok());

    let new_contracts = gather_contracts(&protocol, res.unwrap());

    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(new_contracts.gateway.contract_addr.to_string().clone());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.gateway.code_id);

    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(new_contracts.voting_verifier.contract_addr.to_string());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.voting_verifier.code_id);

    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(new_contracts.multisig_prover.contract_addr.to_string());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.multisig_prover.code_id);
}

#[test]
fn coordinator_one_click_instantiates_contracts_same_chainname_different_deployment_names_succeeds()
{
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");

    assert!(deploy_chains(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        nonempty::String::try_from("testchain1").unwrap(),
        Binary::new(vec![1]),
        false
    )
    .is_ok());
    assert!(deploy_chains(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        nonempty::String::try_from("testchain2").unwrap(),
        Binary::new(vec![2]),
        false
    )
    .is_ok());
}

#[test]
fn coordinator_one_click_instantiates_contracts_different_chainname_different_deployment_names_succeeds(
) {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name_1 = String::from("testchain1");
    let chain_name_2 = String::from("testchain2");

    assert!(deploy_chains(
        &mut protocol,
        chain_name_1.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name_1).unwrap(),
        Binary::new(vec![1]),
        false
    )
    .is_ok());
    assert!(deploy_chains(
        &mut protocol,
        chain_name_2.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name_2).unwrap(),
        Binary::new(vec![2]),
        false
    )
    .is_ok());
}

#[test]
fn coordinator_one_click_instantiates_contracts_different_chainname_same_deployment_names_fails() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name_1 = String::from("testchain1");
    let chain_name_2 = String::from("testchain2");

    assert!(deploy_chains(
        &mut protocol,
        chain_name_1.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name_1.clone()).unwrap(),
        Binary::new(vec![1]),
        false
    )
    .is_ok());
    assert!(deploy_chains(
        &mut protocol,
        chain_name_2.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name_1).unwrap(),
        Binary::new(vec![2]),
        false
    )
    .is_err());
}

#[test]
fn coordinator_one_click_instantiates_contracts_same_chainname_same_deployment_names_fails() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");

    assert!(deploy_chains(
        &mut protocol,
        chain_name.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name.clone()).unwrap(),
        Binary::new(vec![1]),
        false
    )
    .is_ok());
    assert!(deploy_chains(
        &mut protocol,
        chain_name.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name.clone()).unwrap(),
        Binary::new(vec![2]),
        false
    )
    .is_err());
}

#[test]
fn coordinator_one_click_message_verification_and_routing_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        chain2,
        verifiers,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");

    let deployed_chain_msgs = vec![Message {
        cc_id: CrossChainId::new(
            chain_name.clone(),
            "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3",
        )
        .unwrap(),
        source_address: "0xBf12773B490e1Deb57039061AAcFA2A87DEaC9b9"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: chain2.chain_name.clone(),
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];

    let incoming_msgs = vec![Message {
        cc_id: CrossChainId::new(
            chain1.chain_name.clone(),
            "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3",
        )
        .unwrap(),
        source_address: "0xBf12773B490e1Deb57039061AAcFA2A87DEaC9b9"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: chain_name.parse().unwrap(),
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];

    let res = deploy_chains(
        &mut protocol,
        chain_name.clone().as_str(),
        &chain1,
        nonempty::String::try_from(chain_name.clone()).unwrap(),
        Binary::new(vec![1]),
        true,
    );
    assert!(res.is_ok());

    // Verify Messages

    for verifier in &verifiers {
        assert!(protocol
            .service_registry
            .execute(
                &mut protocol.app,
                verifier.addr.clone(),
                &service_registry::msg::ExecuteMsg::RegisterChainSupport {
                    service_name: protocol.service_name.parse().unwrap(),
                    chains: vec![chain_name.parse().unwrap(),]
                }
            )
            .is_ok());
    }

    let contracts = gather_contracts(&protocol, res.unwrap());
    assert!(contracts
        .gateway
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &gateway::msg::ExecuteMsg::VerifyMessages(deployed_chain_msgs.clone())
        )
        .is_ok());

    // Verify messages
    let res = chain1.gateway.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &gateway::msg::ExecuteMsg::VerifyMessages(incoming_msgs.clone()),
    );

    assert!(res.is_ok());
    let res = res.unwrap();
    let mut poll_id: Option<u64> = None;

    for e in &res.events {
        if e.ty == "wasm-messages_poll_started" {
            for att in &e.attributes {
                if att.key == "poll_id" {
                    let v: Result<u64, _> =
                        att.value.trim_matches(|c| c == '"' || c == '/').parse();
                    assert!(v.is_ok());
                    poll_id = Some(v.unwrap());
                }
            }
        }
    }

    assert!(poll_id.is_some());

    // Vote on message success
    for v in &verifiers {
        assert!(chain1
            .voting_verifier
            .execute(
                &mut protocol.app,
                v.addr.clone(),
                &voting_verifier::msg::ExecuteMsg::Vote {
                    poll_id: PollId::from(poll_id.unwrap()),
                    votes: vec![Vote::SucceededOnChain],
                }
            )
            .is_ok());
    }

    // Check that the vote passed
    let res: Result<Vec<voting_verifier::msg::MessageStatus>, cosmwasm_std::StdError> =
        chain1.voting_verifier.query(
            &protocol.app,
            &voting_verifier::msg::QueryMsg::MessagesStatus(incoming_msgs.clone()),
        );
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap()[0].status,
        VerificationStatus::SucceededOnSourceChain
    );

    // Route messages to the new gateway
    assert!(chain1
        .gateway
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &gateway::msg::ExecuteMsg::RouteMessages(incoming_msgs.clone())
        )
        .is_ok());

    // Update verifier set in the prover
    assert!(contracts
        .multisig_prover
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet {}
        )
        .is_ok());

    // Check that a proof for the incoming message can be created
    assert!(contracts
        .multisig_prover
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &multisig_prover::msg::ExecuteMsg::ConstructProof(vec![CrossChainId::new(
                chain1.chain_name.clone(),
                "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3",
            )
            .unwrap()])
        )
        .is_ok());
}

#[test]
fn coordinator_one_click_query_verifier_info_succeeds() {
    let test_utils::TestCase {
        protocol,
        verifiers,
        ..
    } = test_utils::setup_test_case();

    assert!(protocol
        .coordinator
        .query::<coordinator::msg::VerifierInfo>(
            &protocol.app,
            &coordinator::msg::QueryMsg::VerifierInfo {
                service_name: protocol.service_name.to_string(),
                verifier: verifiers[0].addr.to_string(),
            }
        )
        .is_ok());
}

#[test]
fn coordinator_one_click_query_verifier_info_fails() {
    let test_utils::TestCase { protocol, .. } = test_utils::setup_test_case();

    let res = protocol
        .coordinator
        .query::<coordinator::msg::VerifierInfo>(
            &protocol.app,
            &coordinator::msg::QueryMsg::VerifierInfo {
                service_name: protocol.service_name.to_string(),
                verifier: MockApi::default().addr_make("random_verifier").to_string(),
            },
        );

    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains(&service_registry_api::error::ContractError::VerifierNotFound.to_string()));
}

#[test]
fn coordinator_one_click_register_deployment_with_router_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");
    let deployment_name = nonempty_str!("testchain-1");

    let res = deploy_chains(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
        false,
    );
    assert!(res.is_ok());

    let contracts = gather_contracts(&protocol, res.unwrap());

    assert!(protocol
        .coordinator
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &coordinator::msg::ExecuteMsg::RegisterDeployment { deployment_name },
        )
        .is_ok());

    let res = protocol.router.query::<router_api::ChainEndpoint>(
        &protocol.app,
        &router_api::msg::QueryMsg::ChainInfo(
            router_api::ChainName::try_from(chain_name.clone()).unwrap(),
        ),
    );

    assert!(res.is_ok());
    let res = res.unwrap();

    assert_eq!(res.gateway.address, contracts.gateway.contract_addr);
    assert_eq!(res.name, chain_name);
}
