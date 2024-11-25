use std::str::FromStr;

use axelar_wasm_std::nonempty;
use router_api::{Address, CrossChainId, Message};
use cosmwasm_std::{Addr, HexBinary, Uint128};
use multisig::key::KeyType;
use integration_tests::contract::Contract;
use xrpl_types::msg::{CrossChainMessage, XRPLUserMessage, XRPLMessage, XRPLUserMessageWithPayload};
use xrpl_types::types::{TxHash, XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenOrXrp};
use interchain_token_service as its;
use ethers_core::utils::keccak256;

use crate::test_utils::AXL_DENOMINATION;

pub mod test_utils;

/// Tests that a single message can be routed fully through the protocol. Submits a message to the
/// gateway, votes on the poll, routes the message to the outgoing gateway, triggers signing at the prover
/// and signs via multisig. Also tests that rewards are distributed as expected for voting and signing.
#[test]
fn single_message_can_be_verified_and_routed_and_proven_and_rewards_are_distributed() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        chain2,
        verifiers,
        ..
    } = test_utils::setup_test_case();

    let msgs = vec![Message {
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
        destination_chain: chain2.chain_name.clone(),
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];
    let msg_ids: Vec<CrossChainId> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) = test_utils::verify_messages(&mut protocol.app, &chain1.gateway, &msgs);

    // do voting
    test_utils::vote_success(
        &mut protocol.app,
        &chain1.voting_verifier,
        msgs.len(),
        &verifiers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &chain1.voting_verifier, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &chain1.gateway, &msgs);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::messages_from_gateway(&mut protocol.app, &chain2.gateway, &msg_ids);
    assert_eq!(found_msgs, msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol,
        &chain2.multisig_prover,
        &msgs,
        &verifiers,
    );

    let proof = test_utils::proof(&mut protocol.app, &chain2.multisig_prover, &session_id);

    // proof should be complete by now
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
    assert_eq!(proof.message_ids, msg_ids);

    // Advance the height to be able to distribute rewards
    test_utils::advance_height(
        &mut protocol.app,
        u64::from(protocol.rewards_params.epoch_duration) * 2,
    );

    test_utils::distribute_rewards(
        &mut protocol,
        &chain1.chain_name,
        chain1.voting_verifier.contract_addr.clone(),
    );

    let protocol_multisig_address = protocol.multisig.contract_addr.clone();
    test_utils::distribute_rewards(&mut protocol, &chain2.chain_name, protocol_multisig_address);

    // rewards split evenly amongst all verifiers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(verifiers.len() as u64)
        * Uint128::from(2u64);

    for verifier in verifiers {
        let balance = protocol
            .app
            .wrap()
            .query_balance(verifier.addr, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}

#[test]
fn xrpl_ticket_create_can_be_proven() {
    let test_utils::XRPLDestinationTestCase {
        mut protocol,
        xrpl,
        verifiers,
        ..
    } = test_utils::setup_xrpl_destination_test_case();

    /* Create tickets */
    let session_id = test_utils::construct_xrpl_ticket_create_proof_and_sign(
        &mut protocol,
        &xrpl.multisig_prover,
        &verifiers,
    );

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover,
        &session_id,
    );
    assert!(matches!(
        proof,
        xrpl_multisig_prover::msg::ProofResponse::Completed { .. }
    ));
    println!("TicketCreate proof: {:?}", proof);

    let proof_msgs = vec![XRPLMessage::ProverMessage(
        HexBinary::from_hex("9c2f220fe5ee650b3cd10b0a72af1206b3912afce8376214234354180198c5d5")
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    )];

    let (poll_id, expiry) = test_utils::verify_xrpl_messages(
        &mut protocol.app,
        &xrpl.gateway,
        &proof_msgs,
    );
    test_utils::vote_success(
        &mut protocol.app,
        &xrpl.voting_verifier,
        proof_msgs.len(),
        &verifiers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier, poll_id);

    test_utils::xrpl_confirm_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover,
        verifiers.iter().map(|w| (KeyType::Ecdsa, HexBinary::from(w.key_pair.encoded_verifying_key())).try_into().unwrap()).collect(),
        session_id,
        proof_msgs[0].tx_id(),
    );
}

#[test]
fn xrpl_trust_line_can_be_proven() {
    let test_utils::XRPLDestinationTestCase {
        mut protocol,
        xrpl,
        verifiers,
        ..
    } = test_utils::setup_xrpl_destination_test_case();

    let xrpl_token = XRPLToken {
        currency: XRPLCurrency::try_from("BTC".to_string()).unwrap(),
        issuer: XRPLAccountId::from_str("rNYjPW7NbiVDYy6K23b8ye6iZnowj4PsL7").unwrap(),
    };

    test_utils::xrpl_register_local_token(
        &mut protocol.app,
        xrpl.admin.clone(),
        &xrpl.gateway,
        xrpl_token.clone()
    );

    /* Create trust line */
    let session_id = test_utils::construct_xrpl_trust_set_proof_and_sign(
        &mut protocol,
        xrpl.admin,
        &xrpl.multisig_prover,
        &verifiers,
        xrpl_token,
    );

    // TODO: deduplicate all next steps with TicketCreate

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover,
        &session_id,
    );
    assert!(matches!(
        proof,
        xrpl_multisig_prover::msg::ProofResponse::Completed { .. }
    ));
    println!("TrustSet proof: {:?}", proof);

    let proof_msgs = vec![XRPLMessage::ProverMessage(
        HexBinary::from_hex("2b67bbc8011a757087c3a263e41375ee2714a83f852a6d8fce7ee2baf5210d53")
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    )];

    let (poll_id, expiry) = test_utils::verify_xrpl_messages(
        &mut protocol.app,
        &xrpl.gateway,
        &proof_msgs,
    );
    test_utils::vote_success(
        &mut protocol.app,
        &xrpl.voting_verifier,
        proof_msgs.len(),
        &verifiers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier, poll_id);

    test_utils::xrpl_confirm_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover,
        verifiers.iter().map(|w| (KeyType::Ecdsa, HexBinary::from(w.key_pair.encoded_verifying_key())).try_into().unwrap()).collect(),
        session_id,
        proof_msgs[0].tx_id(),
    );
}


#[test]
fn payment_from_xrpl_can_be_verified_and_routed_and_proven() {
    let test_utils::XRPLSourceTestCase {
        mut protocol,
        xrpl,
        axelarnet,
        its_hub,
        destination_chain,
        verifiers,
        ..
    } = test_utils::setup_xrpl_source_test_case();

    let source_address: XRPLAccountId = XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap();
    let destination_address: nonempty::HexBinary = nonempty::HexBinary::try_from(HexBinary::from_hex("95181d16cfb23Bc493668C17d973F061e30F2EAF").unwrap()).unwrap();

    let destination_chain_name = destination_chain.chain_name.clone();
    let amount = XRPLPaymentAmount::Drops(1000000); // 1 XRP
    let payload: Option<nonempty::HexBinary> = None;

    let xrpl_user_msg = XRPLUserMessage {
        tx_id: TxHash::new([0; 32]), // TODO
        source_address: source_address.clone(),
        destination_chain: destination_chain_name.clone(),
        destination_address: destination_address.clone(),
        payload_hash: [0; 32],
        amount,
    };

    let xrpl_msg = XRPLMessage::UserMessage(xrpl_user_msg.clone());

    let xrpl_msg_with_payload = XRPLUserMessageWithPayload {
        message: xrpl_user_msg,
        payload: payload.clone(),
    };

    let interchain_transfer_msg = its::Message::InterchainTransfer {
        token_id: XRPLTokenOrXrp::Xrp.token_id(),
        source_address: nonempty::HexBinary::try_from(HexBinary::from(source_address.as_bytes())).unwrap(),
        destination_address,
        amount: nonempty::Uint256::try_from(1000000000000000000u64).unwrap(),
        // amount: Uint256::from(1000000u128), // 1 XRP
        data: payload,
    };

    let wrapped_payload = its::HubMessage::SendToHub {
        message: interchain_transfer_msg.clone(),
        destination_chain: destination_chain_name.clone().into(),
    }.abi_encode();

    let wrapped_msg = Message {
        cc_id: CrossChainId {
            source_chain: xrpl.chain_name.clone().into(),
            message_id: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string()
                .try_into()
                .unwrap(),
        },
        source_address: Address::from_str(&xrpl.its_address).unwrap(),
        destination_address: Address::try_from(its_hub.contract_addr.to_string()).unwrap(),
        destination_chain: axelarnet.chain_name.clone(),
        payload_hash: keccak256(wrapped_payload.clone()),
    };

    let wrapped_msgs = vec![wrapped_msg.clone()];
    let xrpl_msgs = vec![xrpl_msg.clone()];
    let xrpl_msgs_with_payload = vec![xrpl_msg_with_payload.clone()];
    let xrpl_msg_ids = vec![xrpl_msg.cc_id(xrpl.chain_name.clone().into())];

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) =
        test_utils::verify_xrpl_messages(&mut protocol.app, &xrpl.gateway, &xrpl_msgs);

    // do voting
    test_utils::vote_success(
        &mut protocol.app,
        &xrpl.voting_verifier,
        xrpl_msgs.len(),
        &verifiers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier, poll_id);

    // should be verified, now route
    test_utils::xrpl_route_incoming_messages(&mut protocol.app, &xrpl.gateway, &xrpl_msgs_with_payload);

    // check that the message can be found at the outgoing gateway
    let executable_msgs =
        test_utils::executable_messages_from_axelarnet_gateway(&mut protocol.app, &axelarnet.gateway, &xrpl_msg_ids);
    assert_eq!(executable_msgs.len(), 1);
    if let axelarnet_gateway::ExecutableMessage::Approved(approved_msg) = executable_msgs.first().unwrap() {
        assert_eq!(*approved_msg, wrapped_msg)
    } else {
        unreachable!()
    };

    let its_hub_msg_id = test_utils::execute_axelarnet_gateway_message(
        &mut protocol,
        &axelarnet.gateway,
        wrapped_msg.cc_id.clone(),
        HexBinary::from(wrapped_payload),
    );

    test_utils::route_axelarnet_gateway_messages(
        &mut protocol,
        &axelarnet.gateway,
        wrapped_msgs.clone(),
    );

    let its_hub_msg_ids = vec![CrossChainId::new(axelarnet.chain_name.clone(), its_hub_msg_id).unwrap()];
    let routable_msgs =
        test_utils::routable_messages_from_axelarnet_gateway(&mut protocol.app, &axelarnet.gateway, &its_hub_msg_ids);
    assert_eq!(routable_msgs.len(), 1);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::messages_from_gateway(&mut protocol.app, &destination_chain.gateway, &its_hub_msg_ids);
    assert_eq!(found_msgs, routable_msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol,
        &destination_chain.multisig_prover,
        &routable_msgs,
        &verifiers,
    );

    let proof = test_utils::proof(&mut protocol.app, &destination_chain.multisig_prover, &session_id);

    // proof should be complete by now
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
    assert_eq!(proof.message_ids, its_hub_msg_ids);

    // Advance the height to be able to distribute rewards
    test_utils::advance_height(
        &mut protocol.app,
        u64::from(protocol.rewards_params.epoch_duration) * 2,
    );

    test_utils::distribute_rewards(
        &mut protocol,
        &xrpl.chain_name,
        xrpl.voting_verifier.contract_addr.clone(),
    );

    let protocol_multisig_address = protocol.multisig.contract_addr.clone();
    test_utils::distribute_rewards(&mut protocol, &destination_chain_name, protocol_multisig_address);

    // rewards split evenly amongst all verifiers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(verifiers.len() as u64)
        * Uint128::from(2u64);

    for verifier in verifiers {
        let balance = protocol
            .app
            .wrap()
            .query_balance(verifier.addr, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}

#[test]
fn payment_towards_xrpl_can_be_verified_and_routed_and_proven() {
    let test_utils::XRPLDestinationTestCase {
        mut protocol,
        source_chain,
        axelarnet,
        its_hub,
        xrpl,
        verifiers,
        ..
    } = test_utils::setup_xrpl_destination_test_case();

    let source_address: Address = "0x95181d16cfb23Bc493668C17d973F061e30F2EAF"
        .to_string()
        .try_into()
        .unwrap();

    let destination_address: XRPLAccountId = XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap();

    let destination_chain = xrpl.chain_name.clone();
    let amount = nonempty::Uint256::try_from(1000000000000000000u64).unwrap(); // 1 wrapped-XRP
    let payload: Option<nonempty::HexBinary> = None;

    let interchain_transfer_msg = its::Message::InterchainTransfer {
        token_id: XRPLTokenOrXrp::Xrp.token_id(),
        source_address: nonempty::HexBinary::try_from(HexBinary::from(source_address.as_bytes())).unwrap(),
        destination_address: nonempty::HexBinary::try_from(HexBinary::from(destination_address.as_bytes())).unwrap(),
        amount,
        data: payload,
    };

    let wrapped_payload = its::HubMessage::SendToHub {
        message: interchain_transfer_msg.clone(),
        destination_chain: destination_chain.into(),
    }.abi_encode();

    let wrapped_msg = Message {
        cc_id: CrossChainId {
            source_chain: source_chain.chain_name.clone().into(),
            message_id: "0xaff42a67c474758ce97bd9b69c395c6dc6019707b400e06c30b0878a9357b2ea-3"
                .to_string()
                .try_into()
                .unwrap(),
        },
        source_address: source_chain.its_address,
        destination_address: Address::try_from(its_hub.contract_addr.to_string()).unwrap(),
        destination_chain: axelarnet.chain_name.clone(),
        payload_hash: keccak256(wrapped_payload.clone()),
    };
    let wrapped_msg_id: CrossChainId = wrapped_msg.cc_id.clone();
    let wrapped_msgs = vec![wrapped_msg.clone()];
    let wrapped_msg_ids = vec![wrapped_msg_id.clone()];

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) =
        test_utils::verify_messages(&mut protocol.app, &source_chain.gateway, &wrapped_msgs);

    // do voting
    test_utils::vote_success(
        &mut protocol.app,
        &source_chain.voting_verifier,
        wrapped_msgs.len(),
        &verifiers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &source_chain.voting_verifier, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &source_chain.gateway, &wrapped_msgs);

    // check that the message can be found at the outgoing gateway
    let executable_msgs =
        test_utils::executable_messages_from_axelarnet_gateway(&mut protocol.app, &axelarnet.gateway, &wrapped_msg_ids);
    assert_eq!(executable_msgs.len(), 1);
    if let axelarnet_gateway::ExecutableMessage::Approved(approved_msg) = executable_msgs.first().unwrap() {
        assert_eq!(*approved_msg, wrapped_msg)
    } else {
        unreachable!()
    };

    let its_hub_msg_id = test_utils::execute_axelarnet_gateway_message(
        &mut protocol,
        &axelarnet.gateway,
        wrapped_msg.cc_id.clone(),
        HexBinary::from(wrapped_payload),
    );

    test_utils::route_axelarnet_gateway_messages(
        &mut protocol,
        &axelarnet.gateway,
        wrapped_msgs.clone(),
    );

    let its_hub_msg_ids = vec![CrossChainId::new(axelarnet.chain_name.clone(), its_hub_msg_id).unwrap()];
    let routable_msgs =
        test_utils::routable_messages_from_axelarnet_gateway(&mut protocol.app, &axelarnet.gateway, &its_hub_msg_ids);
    assert_eq!(routable_msgs.len(), 1);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::messages_from_xrpl_gateway(&mut protocol.app, &xrpl.gateway, &its_hub_msg_ids);
    assert_eq!(found_msgs, routable_msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_xrpl_payment_proof_and_sign(
        &mut protocol,
        &xrpl.multisig_prover,
        routable_msgs.first().unwrap().clone(),
        &verifiers,
        its::HubMessage::ReceiveFromHub {
            source_chain: source_chain.chain_name.clone().into(),
            message: interchain_transfer_msg,
        }.abi_encode(),
    );

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover,
        &session_id,
    );
    println!("Payment proof: {:?}", proof);
    assert!(matches!(
        //proof.status,
        proof,
        xrpl_multisig_prover::msg::ProofResponse::Completed { .. }
    ));

    let proof_msgs = vec![XRPLMessage::ProverMessage(
        HexBinary::from_hex("e369c370d039d0711690341dc5c75c42281a19222260a0ea6c6f9f268cf8a092")
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    )];

    let (poll_id, expiry) = test_utils::verify_xrpl_messages(
        &mut protocol.app,
        &xrpl.gateway,
        &proof_msgs
    );
    test_utils::vote_success(
        &mut protocol.app,
        &xrpl.voting_verifier,
        proof_msgs.len(),
        &verifiers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier, poll_id);

    test_utils::xrpl_confirm_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover,
        verifiers.iter().map(|w| (KeyType::Ecdsa, HexBinary::from(w.key_pair.encoded_verifying_key())).try_into().unwrap()).collect(),
        session_id,
        proof_msgs[0].tx_id(),
    );

    // Advance the height to be able to distribute rewards
    test_utils::advance_height(
        &mut protocol.app,
        u64::from(protocol.rewards_params.epoch_duration) * 2,
    );

    test_utils::distribute_rewards(&mut protocol, &xrpl.chain_name, xrpl.voting_verifier.contract_addr.clone());
    test_utils::distribute_rewards(&mut protocol, &source_chain.chain_name, source_chain.voting_verifier.contract_addr.clone());

    let protocol_multisig_address = protocol.multisig.contract_addr.clone();
    test_utils::distribute_rewards(&mut protocol, &source_chain.chain_name, protocol_multisig_address);

    // rewards split evenly amongst all workers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(verifiers.len() as u64)
        * Uint128::from(2u64);

    for verifier in verifiers {
        let balance = protocol
            .app
            .wrap()
            .query_balance(verifier.addr, test_utils::AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}


#[test]
fn routing_to_incorrect_gateway_interface() {
    let test_utils::TestCase {
        mut protocol,
        chain1,
        chain2,
        ..
    } = test_utils::setup_test_case();

    let msgs = [Message {
        cc_id: CrossChainId::new(
            chain1.chain_name.clone(),
            "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3",
        )
        .unwrap(),
        source_address: "0xBf12773B49()0e1Deb57039061AAcFA2A87DEaC9b9"
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

    test_utils::upgrade_gateway(
        &mut protocol.app,
        &protocol.router,
        &protocol.governance_address,
        &chain2.chain_name,
        Addr::unchecked("some random address")
            .to_string()
            .try_into()
            .unwrap(), // gateway address does not implement required interface,
    );

    let response = protocol.router.execute(
        &mut protocol.app,
        chain1.gateway.contract_addr.clone(),
        &router_api::msg::ExecuteMsg::RouteMessages(msgs.to_vec()),
    );
    assert!(response.is_err())
}
