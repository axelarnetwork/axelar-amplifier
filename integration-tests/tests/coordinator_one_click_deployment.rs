use axelar_wasm_std::Threshold;
use cosmwasm_std::Addr;
use integration_tests::contract::Contract;
use multisig::key::KeyType;
use multisig_prover_api::encoding::Encoder;

pub mod test_utils;

#[test]
fn coordinator_one_click_deployment() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        ..
    } = test_utils::setup_test_case();

    let res = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &coordinator::msg::ExecuteMsg::DeployChain {
            chain_name: "testchain".parse().unwrap(),
            params: Box::new(coordinator::msg::DeploymentParams::Manual {
                gateway_code_id: chain1.gateway.code_id,
                gateway_label: "Gateway1.0.0".to_string(),
                verifier_code_id: chain1.voting_verifier.code_id,
                verifier_label: "Verifier1.0.0".to_string(),
                verifier_msg: coordinator::msg::VerifierMsg {
                    governance_address: protocol.governance_address.to_string(),
                    service_name: protocol.service_name.parse().unwrap(),
                    source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5".to_string(),
                    voting_threshold: Threshold::try_from((3, 4)).unwrap().try_into().unwrap(),
                    block_expiry: 10.try_into().unwrap(),
                    confirmation_height: 5,
                    source_chain: "testchain".parse().unwrap(),
                    rewards_address: protocol
                        .rewards
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                    address_format: axelar_wasm_std::address::AddressFormat::Eip55,
                },
                prover_code_id: chain1.multisig_prover.code_id,
                prover_label: "Prover1.0.0".to_string(),
                prover_msg: coordinator::msg::ProverMsg {
                    governance_address: protocol.governance_address.to_string(),
                    multisig_address: protocol.multisig.contract_addr.to_string(),
                    signing_threshold: Threshold::try_from((2u64, 3u64))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    service_name: protocol.service_name.parse().unwrap(),
                    chain_name: "testchain".parse().unwrap(),
                    verifier_set_diff_threshold: 0,
                    encoder: Encoder::Abi,
                    key_type: KeyType::Ecdsa,
                    domain_separator: [0; 32],
                },
            }),
        },
    );

    println!("Check the stuff: {:?}", res);
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
