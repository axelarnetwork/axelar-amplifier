use std::collections::HashMap;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, Threshold, VerificationStatus};
use cosmwasm_std::{coins, Addr, HexBinary, Uint128};
use cw_multi_test::AppResponse;
use error_stack::Report;
use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::protocol::Protocol;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::KeyType;
use multisig_prover_api::encoding::Encoder;
use rewards::PoolId;
use router_api::{CrossChainId, Message};

use crate::test_utils::{Chain, AXL_DENOMINATION};

pub mod test_utils;

struct DeployedContracts {
    gateway: GatewayContract,
    voting_verifier: VotingVerifierContract,
    multisig_prover: MultisigProverContract,
}

fn deploy_chains(
    protocol: &mut Protocol,
    chain: &Chain,
    chain_name: &str,
) -> Result<AppResponse, Report<ContractError>> {
    let res = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::DeployChain {
            chain_name: chain_name.parse().unwrap(),
            params: Box::new(coordinator::msg::DeploymentParams::Manual {
                gateway_code_id: chain.gateway.code_id,
                gateway_label: "Gateway1.0.0".to_string(),
                verifier_code_id: chain.voting_verifier.code_id,
                verifier_label: "Verifier1.0.0".to_string(),
                verifier_msg: coordinator::msg::VerifierMsg {
                    governance_address: protocol.governance_address.to_string(),
                    service_name: protocol.service_name.parse().unwrap(),
                    source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5"
                        .to_string(),
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
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                    address_format: axelar_wasm_std::address::AddressFormat::Eip55,
                },
                prover_code_id: chain.multisig_prover.code_id,
                prover_label: "Prover1.0.0".to_string(),
                prover_msg: coordinator::msg::ProverMsg {
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
            }),
        },
    )?;

    let contracts = gather_contracts(&protocol, res.clone());

    let response = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::RegisterProverContract {
            chain_name: chain_name.parse().unwrap(),
            new_prover_addr: contracts.multisig_prover.contract_addr.to_string(),
        },
    );
    assert!(response.is_ok());

    protocol.multisig.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCallers {
            contracts: HashMap::from([(
                contracts.multisig_prover.contract_addr.to_string(),
                chain_name.parse().unwrap(),
            )]),
        },
    )?;

    protocol.router.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &router_api::msg::ExecuteMsg::RegisterChain {
            chain: chain_name.parse().unwrap(),
            gateway_address: contracts
                .gateway
                .contract_addr
                .to_string()
                .try_into()
                .unwrap(),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        },
    )?;

    let rewards_params = rewards::msg::Params {
        epoch_duration: nonempty::Uint64::try_from(10u64).unwrap(),
        rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
        participation_threshold: (1, 2).try_into().unwrap(),
    };

    protocol.rewards.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &rewards::msg::ExecuteMsg::CreatePool {
            pool_id: PoolId {
                chain_name: chain_name.parse().unwrap(),
                contract: contracts.voting_verifier.contract_addr.to_string(),
            },
            params: rewards_params.clone(),
        },
    )?;

    protocol.rewards.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &rewards::msg::ExecuteMsg::CreatePool {
            pool_id: PoolId {
                chain_name: chain_name.parse().unwrap(),
                contract: protocol.multisig.contract_addr.to_string(),
            },
            params: rewards_params,
        },
    )?;

    protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.parse().unwrap(),
                contract: contracts.voting_verifier.contract_addr.to_string(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    )?;

    protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.parse().unwrap(),
                contract: protocol.multisig.contract_addr.to_string(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    )?;

    Ok(res)
}

fn gather_contracts(protocol: &Protocol, app_response: AppResponse) -> DeployedContracts {
    let mut gateway = GatewayContract::default();
    let mut voting_verifier = VotingVerifierContract::default();
    let mut multisig_prover = MultisigProverContract::default();

    for e in app_response.events {
        if e.ty == "wasm-coordinator_deploy_contracts" {
            for attribute in e.attributes {
                if attribute.key == "gateway_address" {
                    gateway.contract_addr = Addr::unchecked(attribute.value);
                } else if attribute.key == "voting_verifier_address" {
                    voting_verifier.contract_addr = Addr::unchecked(attribute.value);
                } else if attribute.key == "multisig_prover_address" {
                    multisig_prover.contract_addr = Addr::unchecked(attribute.value);
                } else if attribute.key == "gateway_code_id" {
                    gateway.code_id = attribute.value.parse().unwrap();
                } else if attribute.key == "voting_verifier_code_id" {
                    voting_verifier.code_id = attribute.value.parse().unwrap();
                } else if attribute.key == "multisig_prover_code_id" {
                    multisig_prover.code_id = attribute.value.parse().unwrap();
                }
            }
        }
    }

    multisig_prover.admin_addr = protocol.governance_address.clone();

    DeployedContracts {
        gateway,
        voting_verifier,
        multisig_prover,
    }
}

#[test]
fn coordinator_one_click_deployment_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let res = deploy_chains(&mut protocol, &chain1, "testchain");
    assert!(res.is_ok());
    let res = res.unwrap();

    // TODO: Make test more succinct, and check inter-contract dependencies
    let mut gateway_addr = Addr::unchecked("");
    let mut verifier_addr = Addr::unchecked("");
    let mut prover_addr = Addr::unchecked("");

    let mut computed_gateway_addr = Addr::unchecked("");
    let mut computed_verifier_addr = Addr::unchecked("");
    let mut computed_prover_addr = Addr::unchecked("");

    for e in res.events.clone() {
        if e.ty == "instantiate" {
            let mut addr_ref: Option<&mut Addr> = None;
            let mut addr: Option<String> = None;
            let mut c_id: Option<u64> = None;
            for attribute in e.attributes.clone() {
                if attribute.key == "code_id" {
                    if attribute.value == chain1.gateway.code_id.to_string().clone() {
                        addr_ref = Some(&mut gateway_addr);
                    } else if attribute.value == chain1.voting_verifier.code_id.to_string().clone()
                    {
                        addr_ref = Some(&mut verifier_addr);
                    } else if attribute.value == chain1.multisig_prover.code_id.to_string().clone()
                    {
                        addr_ref = Some(&mut prover_addr);
                    }

                    match addr {
                        Some(a) => {
                            if let Some(ref mut a_ref) = addr_ref {
                                **a_ref = Addr::unchecked(a);
                            }
                            addr = None;
                        }
                        None => {
                            c_id = Some(attribute.value.parse().unwrap());
                        }
                    }
                } else if attribute.key == "_contract_address" {
                    match c_id {
                        Some(id) => {
                            addr_ref = None;
                            if id == chain1.gateway.code_id {
                                gateway_addr = Addr::unchecked(attribute.value.clone());
                            } else if id == chain1.voting_verifier.code_id {
                                verifier_addr = Addr::unchecked(attribute.value.clone());
                            } else if id == chain1.multisig_prover.code_id {
                                prover_addr = Addr::unchecked(attribute.value.clone());
                            }
                        }
                        None => {
                            addr = Some(attribute.value);
                        }
                    }
                }
            }
        }
    }

    for e in res.events {
        if e.ty == "wasm-coordinator_deploy_contracts" {
            for attribute in e.attributes {
                if attribute.key == "gateway_address" {
                    computed_gateway_addr = Addr::unchecked(attribute.value);
                } else if attribute.key == "voting_verifier_address" {
                    computed_verifier_addr = Addr::unchecked(attribute.value);
                } else if attribute.key == "multisig_prover_address" {
                    computed_prover_addr = Addr::unchecked(attribute.value);
                }
            }
        }
    }

    // Verify that the contracts were deployed and that the pre-computed address
    // are the same as the new addresses (as returned by the instantiate2 events).
    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(gateway_addr.to_string().clone());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.gateway.code_id);
    assert_eq!(gateway_addr, computed_gateway_addr);

    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(verifier_addr.to_string());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.voting_verifier.code_id);
    assert_eq!(verifier_addr, computed_verifier_addr);

    let res = protocol
        .app
        .wrap()
        .query_wasm_contract_info(prover_addr.to_string());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().code_id, chain1.multisig_prover.code_id);
    assert_eq!(prover_addr, computed_prover_addr);
}

#[test]
fn coordinator_one_click_duplicate_deployment_fails() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name = String::from("testchain");

    assert!(deploy_chains(&mut protocol, &chain1, chain_name.as_str()).is_ok());
    assert!(deploy_chains(&mut protocol, &chain1, chain_name.as_str()).is_err());
}

#[test]
fn coordinator_one_click_multiple_deployments_succeeds() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let chain_name_1 = String::from("testchain1");
    let chain_name_2 = String::from("testchain2");

    assert!(deploy_chains(&mut protocol, &chain1, chain_name_1.as_str()).is_ok());
    assert!(deploy_chains(&mut protocol, &chain1, chain_name_2.as_str()).is_ok());
}

#[test]
fn coordinator_one_click_contract_interactions_succeeds() {
    // TODO: Break up into separate tests
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

    let res = deploy_chains(&mut protocol, &chain1, chain_name.as_str());
    assert!(res.is_ok());

    // Verify Messages

    for ref verifier in &verifiers {
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

    // Verify and Route Incoming Messages

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

    assert!(chain1
        .gateway
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &gateway::msg::ExecuteMsg::RouteMessages(incoming_msgs.clone())
        )
        .is_ok());

    assert!(contracts
        .multisig_prover
        .execute(
            &mut protocol.app,
            protocol.governance_address.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet {}
        )
        .is_ok());

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
