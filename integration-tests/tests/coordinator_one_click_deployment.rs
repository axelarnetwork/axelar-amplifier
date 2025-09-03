use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, nonempty_str, Threshold, VerificationStatus};
use coordinator::msg::{
    ChainContractsResponse, ContractDeploymentInfo, DeploymentParams, ManualDeploymentParams,
    ProverMsg, VerifierMsg,
};
use cosmwasm_std::{Binary, HexBinary};
use cw_multi_test::AppResponse;
use error_stack::Report;
use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::protocol::Protocol;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::KeyType;
use multisig_prover_api::encoding::Encoder;
use router_api::{chain_name, cosmos_addr, ChainName, CrossChainId, Message};

use crate::test_utils::Chain;

pub mod test_utils;

const TESTCHAIN: &str = "testchain";
const CHAIN_NAME_1: &str = "testchain1";
const CHAIN_NAME_2: &str = "testchain2";

#[derive(Clone)]
struct DeployedContracts {
    gateway: GatewayContract,
    voting_verifier: VotingVerifierContract,
    multisig_prover: MultisigProverContract,
}

fn instantiate_contracts(
    protocol: &mut Protocol,
    chain_name: &str,
    chain: &Chain,
    deployment_name: nonempty::String,
    salt: Binary,
) -> Result<AppResponse, Report<ContractError>> {
    // Deploy gateway, verifier and prover using InstantiateChainContracts
    protocol.coordinator.execute(
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
                    contract_admin: protocol.governance_address.clone(),
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
                    contract_admin: protocol.governance_address.clone(),
                },
                prover: ContractDeploymentInfo {
                    code_id: chain.multisig_prover.code_id,
                    label: "Prover1.0.0".to_string(),
                    msg: ProverMsg {
                        governance_address: nonempty::String::try_from(
                            protocol.governance_address.to_string(),
                        )
                        .expect("expected non-empty address"),
                        multisig_address: nonempty::String::try_from(
                            protocol.multisig.contract_addr.to_string(),
                        )
                        .expect("expected non-empty address"),
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
                        admin_address: nonempty::String::try_from(
                            protocol.governance_address.to_string(),
                        )
                        .expect("expected non-empty address"),
                    },
                    contract_admin: protocol.governance_address.clone(),
                },
            })),
        },
    )
}

fn register_deployment(
    protocol: &mut Protocol,
    deployment_name: nonempty::String,
) -> Result<AppResponse, Report<ContractError>> {
    protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::RegisterDeployment { deployment_name },
    )
}

fn gather_contracts(
    protocol: &Protocol,
    deployment_name: nonempty::String,
    chain: &Chain,
) -> DeployedContracts {
    let mut gateway = GatewayContract::default();
    let mut voting_verifier = VotingVerifierContract::default();
    let mut multisig_prover = MultisigProverContract::default();

    let res = protocol.coordinator.query::<ChainContractsResponse>(
        &protocol.app,
        &coordinator::msg::QueryMsg::Deployment { deployment_name },
    );
    assert!(res.is_ok());
    let res = res.unwrap();

    gateway.code_id = chain.gateway.code_id;
    gateway.contract_addr = res.gateway_address;
    voting_verifier.code_id = chain.voting_verifier.code_id;
    voting_verifier.contract_addr = res.verifier_address;
    multisig_prover.admin_addr = protocol.governance_address.clone();
    multisig_prover.code_id = chain.multisig_prover.code_id;
    multisig_prover.contract_addr = res.prover_address;

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

    let deployment_name = nonempty::String::try_from("testchaindeploy").unwrap();
    let res = instantiate_contracts(
        &mut protocol,
        "testchain",
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());

    assert!(register_deployment(&mut protocol, deployment_name.clone()).is_ok());

    let new_contracts = gather_contracts(&protocol, deployment_name, &chain1);

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

    assert!(instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        nonempty::String::try_from("testchain1").unwrap(),
        Binary::new(vec![1])
    )
    .is_ok());
    assert!(instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        nonempty::String::try_from("testchain2").unwrap(),
        Binary::new(vec![2])
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

    assert!(instantiate_contracts(
        &mut protocol,
        CHAIN_NAME_1,
        &chain1,
        nonempty::String::try_from(CHAIN_NAME_1).unwrap(),
        Binary::new(vec![1])
    )
    .is_ok());
    assert!(instantiate_contracts(
        &mut protocol,
        CHAIN_NAME_2,
        &chain1,
        nonempty::String::try_from(CHAIN_NAME_2).unwrap(),
        Binary::new(vec![2])
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

    assert!(instantiate_contracts(
        &mut protocol,
        CHAIN_NAME_1,
        &chain1,
        nonempty::String::try_from(CHAIN_NAME_1).unwrap(),
        Binary::new(vec![1])
    )
    .is_ok());
    assert!(instantiate_contracts(
        &mut protocol,
        CHAIN_NAME_2,
        &chain1,
        nonempty::String::try_from(CHAIN_NAME_1).unwrap(),
        Binary::new(vec![2])
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

    assert!(instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        nonempty::String::try_from(TESTCHAIN).unwrap(),
        Binary::new(vec![1])
    )
    .is_ok());
    assert!(instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        nonempty::String::try_from(TESTCHAIN).unwrap(),
        Binary::new(vec![2])
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

    let deployed_chain_msgs = vec![Message {
        cc_id: CrossChainId::new(
            TESTCHAIN,
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
        destination_chain: chain_name!(TESTCHAIN),
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];

    let res = instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        nonempty::String::try_from(TESTCHAIN).unwrap(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());
    assert!(register_deployment(
        &mut protocol,
        nonempty::String::try_from(TESTCHAIN).unwrap()
    )
    .is_ok());

    // Verify Messages

    for verifier in &verifiers {
        assert!(protocol
            .service_registry
            .execute(
                &mut protocol.app,
                verifier.addr.clone(),
                &service_registry::msg::ExecuteMsg::RegisterChainSupport {
                    service_name: protocol.service_name.parse().unwrap(),
                    chains: vec![chain_name!(TESTCHAIN),]
                }
            )
            .is_ok());
    }

    let contracts = gather_contracts(
        &protocol,
        nonempty::String::try_from(TESTCHAIN).unwrap(),
        &chain1,
    );
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
                verifier: cosmos_addr!("random_verifier").to_string(),
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

    let deployment_name = nonempty_str!("testchain-1");

    let res = instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());
    assert!(register_deployment(&mut protocol, deployment_name).is_ok());
}

#[test]
fn coordinator_one_click_authorize_callers_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let deployment_name = nonempty_str!("testchain-1");

    let res = instantiate_contracts(
        &mut protocol,
        TESTCHAIN,
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());

    let contracts = gather_contracts(&protocol, deployment_name.clone(), &chain1);

    assert!(register_deployment(&mut protocol, deployment_name,).is_ok());

    let res = protocol.multisig.query::<bool>(
        &protocol.app,
        &multisig::msg::QueryMsg::IsCallerAuthorized {
            contract_address: contracts.multisig_prover.contract_address().to_string(),
            chain_name: chain_name!(TESTCHAIN),
        },
    );
    assert!(res.is_ok());
    assert!(res.unwrap());
}

#[test]
fn coordinator_one_click_query_deployments_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");
    let deployment_name = nonempty_str!("testchain-1");

    let res = protocol.coordinator.query::<Vec<ChainContractsResponse>>(
        &protocol.app,
        &coordinator::msg::QueryMsg::Deployments {
            start_after: None,
            limit: 1,
        },
    );
    assert!(res.is_ok());
    assert_eq!(res.unwrap().len(), 0);

    let res = instantiate_contracts(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());
<<<<<<< HEAD
    let contracts = gather_contracts(&protocol, deployment_name, &chain1);
=======
    let contracts = gather_contracts(&protocol, res.unwrap());
>>>>>>> main

    let deployments: coordinator::msg::QueryMsg =
        serde_json::from_str(r#"{"deployments" : {}}"#).unwrap();

    let res = protocol
        .coordinator
        .query::<Vec<ChainContractsResponse>>(&protocol.app, &deployments);
    assert!(res.is_ok());

    let res = res.unwrap();
    assert_eq!(res.len(), 1);

    assert!(res[0].eq(&ChainContractsResponse {
        chain_name: ChainName::try_from(chain_name.clone()).unwrap(),
        prover_address: contracts.multisig_prover.contract_addr,
        gateway_address: contracts.gateway.contract_addr,
        verifier_address: contracts.voting_verifier.contract_addr
    }));
}

#[test]
fn coordinator_one_click_query_single_deployment_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");
    let deployment_name = nonempty_str!("testchain-1");

    let res = instantiate_contracts(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());
<<<<<<< HEAD
    let contracts = gather_contracts(&protocol, deployment_name.clone(), &chain1);
=======
    let contracts = gather_contracts(&protocol, res.unwrap());
>>>>>>> main

    let res = protocol.coordinator.query::<ChainContractsResponse>(
        &protocol.app,
        &coordinator::msg::QueryMsg::Deployment { deployment_name },
    );
    assert!(res.is_ok());
    assert!(res.unwrap().eq(&ChainContractsResponse {
        chain_name: ChainName::try_from(chain_name.clone()).unwrap(),
        prover_address: contracts.multisig_prover.contract_addr,
        gateway_address: contracts.gateway.contract_addr,
        verifier_address: contracts.voting_verifier.contract_addr
    }));
}
<<<<<<< HEAD
=======

#[test]
fn coordinator_one_click_query_single_deployment_fails() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");
    let deployment_name = nonempty_str!("testchain-1");

    let res = instantiate_contracts(
        &mut protocol,
        chain_name.as_str(),
        &chain1,
        deployment_name.clone(),
        Binary::new(vec![1]),
    );
    assert!(res.is_ok());

    let res = protocol.coordinator.query::<ChainContractsResponse>(
        &protocol.app,
        &coordinator::msg::QueryMsg::Deployment {
            deployment_name: nonempty_str!("randomdeployment"),
        },
    );
    assert!(res.is_err());
}
>>>>>>> main
