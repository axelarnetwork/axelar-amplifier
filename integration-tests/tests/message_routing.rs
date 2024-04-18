use axelar_wasm_std::VerificationStatus;
use connection_router::state::{Address, CrossChainId, Message};
use cosmwasm_std::{HexBinary, Uint128, Coin};
use multisig::key::KeyType;

use crate::test_utils::ETH_DENOMINATION;

mod test_utils;
/// Tests that a single message can be routed fully through the protocol. Submits a message to the
/// gateway, votes on the poll, routes the message to the outgoing gateway, triggers signing at the prover
/// and signs via multisig. Also tests that rewards are distributed as expected for voting and signing.
#[test]
fn single_message_can_be_verified_and_routed_and_proven_and_rewards_are_distributed() {
    let (mut protocol, chain1, chain2, workers, _) = test_utils::setup_test_case();

    let msgs = vec![Message {
        cc_id: CrossChainId {
            chain: chain1.chain_name.clone(),
            id: "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924:3"
                .to_string()
                .try_into()
                .unwrap(),
        },
        source_address: "0xBf12773B49()0e1Deb57039061AAcFA2A87DEaC9b9"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: chain2.chain_name,
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
    let (poll_id, expiry) =
        test_utils::verify_messages(&mut protocol.app, &chain1.gateway_address, &msgs);

    // do voting
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &chain1.voting_verifier_address,
        msgs.len(),
        &workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &chain1.voting_verifier_address, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &chain1.gateway_address, &msgs);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::get_messages_from_gateway(&mut protocol.app, &chain2.gateway_address, &msg_ids);
    assert_eq!(found_msgs, msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol.app,
        &chain2.multisig_prover_address,
        &protocol.multisig_address,
        &msgs,
        &workers,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &chain2.multisig_prover_address,
        &session_id,
    );

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
        &mut protocol.app,
        &protocol.rewards_address,
        &chain1.voting_verifier_address,
    );
    test_utils::distribute_rewards(
        &mut protocol.app,
        &protocol.rewards_address,
        &protocol.multisig_address,
    );

    // rewards split evenly amongst all workers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(workers.len() as u64)
        * Uint128::from(2u64);

    for worker in workers {
        let balance = protocol
            .app
            .wrap()
            .query_balance(worker.addr, test_utils::AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}

#[test]
fn xrpl_ticket_create_can_be_proven() {
    let (mut protocol, _, xrpl, workers, _) = test_utils::setup_xrpl_destination_test_case();

    /* Create tickets */
    let session_id = test_utils::construct_xrpl_ticket_create_proof_and_sign(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &protocol.multisig_address,
        &workers,
    );

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof,
        xrpl_multisig_prover::msg::GetProofResponse::Completed { .. }
    ));
    println!("TicketCreate proof: {:?}", proof);

    let xrpl_multisig_address = "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(); // TODO: fix duplicate definition
    let proof_msgs = vec![Message {
        destination_chain: xrpl.chain_name.clone(),
        source_address: Address::try_from(xrpl_multisig_address.clone()).unwrap(),
        destination_address: Address::try_from(xrpl_multisig_address).unwrap(),
        cc_id: CrossChainId {
            chain: xrpl.chain_name.clone(),
            id: "9c2f220fe5ee650b3cd10b0a72af1206b3912afce8376214234354180198c5d5:0"
                .to_string()
                .try_into()
                .unwrap(),
        },
        payload_hash: [0; 32],
    }];

    let (poll_id, expiry) = test_utils::verify_messages(
        &mut protocol.app,
        &xrpl.gateway_address,
        &proof_msgs,
    );
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &xrpl.voting_verifier_address,
        1,
        &workers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier_address, poll_id);

    test_utils::xrpl_update_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        workers.iter().map(|w| (KeyType::Ecdsa, HexBinary::from(w.key_pair.encoded_verifying_key())).try_into().unwrap()).collect(),
        session_id,
        proof_msgs[0].cc_id.clone(),
        VerificationStatus::SucceededOnChain
    );
}

#[test]
fn payment_towards_xrpl_can_be_verified_and_routed_and_proven() {
    let (mut protocol, source_chain, xrpl, workers, _) = test_utils::setup_xrpl_destination_test_case();

    let msg = Message {
        cc_id: CrossChainId {
            chain: source_chain.chain_name.clone(),
            id: "0xaff42a67c474758ce97bd9b69c395c6dc6019707b400e06c30b0878a9357b2ea:3"
                .to_string()
                .try_into()
                .unwrap(),
        },
        // TODO: should be 0x address
        source_address: "rhKnz85JUKcrAizwxNUDfqCvaUi9ZMhuwj"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: xrpl.chain_name.clone(),
        // TODO: payload_hash?
        payload_hash: [0; 32],
    };
    let msg_id: CrossChainId = msg.cc_id.clone();
    let msgs = vec![msg.clone()];
    let msg_ids = vec![msg_id.clone()];

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) =
        test_utils::verify_messages(&mut protocol.app, &source_chain.gateway_address, &msgs);

    // do voting
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &source_chain.voting_verifier_address,
        msgs.len(),
        &workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &source_chain.voting_verifier_address, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &source_chain.gateway_address, &msgs);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::get_messages_from_gateway(&mut protocol.app, &xrpl.gateway_address, &msg_ids);
    assert_eq!(found_msgs, msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_xrpl_payment_proof_and_sign(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &protocol.multisig_address,
        msg,
        &workers,
        &[Coin {
            denom: ETH_DENOMINATION.to_string(),
            // amount: Uint128::MAX,
            // amount: Uint128::from(10u128.pow(29)), // scaled down to 10^17 drops = max XRP
            amount: Uint128::from(100000000u128)
        }],
    );

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &session_id,
    );
    println!("Payment proof: {:?}", proof);
    assert!(matches!(
        //proof.status,
        proof,
        xrpl_multisig_prover::msg::GetProofResponse::Completed { .. }
    ));

    let xrpl_multisig_address = "rfEf91bLxrTVC76vw1W3Ur8Jk4Lwujskmb".to_string(); // TODO: fix duplicate definition
    let proof_msgs = vec![Message {
        destination_chain: xrpl.chain_name.clone(),
        source_address: Address::try_from(xrpl_multisig_address).unwrap(),
        destination_address: Address::try_from("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".to_string()).unwrap(),
        cc_id: CrossChainId {
            chain: xrpl.chain_name.clone(),
            id: "c5c80adaff8703e589988f68587535d5c5cac5a7d7b99f0507aee3de40201137:0"
                .to_string()
                .try_into()
                .unwrap(),
        },
        payload_hash: [0; 32],
    }];

    let (poll_id, expiry) = test_utils::verify_messages(
        &mut protocol.app,
        &xrpl.gateway_address,
        &proof_msgs
    );
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &xrpl.voting_verifier_address,
        1,
        &workers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier_address, poll_id);

    test_utils::xrpl_update_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        workers.iter().map(|w| (KeyType::Ecdsa, HexBinary::from(w.key_pair.encoded_verifying_key())).try_into().unwrap()).collect(),
        session_id,
        proof_msgs[0].cc_id.clone(),
        VerificationStatus::SucceededOnChain
    );

    // Advance the height to be able to distribute rewards
    test_utils::advance_height(
        &mut protocol.app,
        u64::from(protocol.rewards_params.epoch_duration) * 2,
    );

    test_utils::distribute_rewards(
        &mut protocol.app,
        &protocol.rewards_address,
        &xrpl.voting_verifier_address,
    );
    test_utils::distribute_rewards(
        &mut protocol.app,
        &protocol.rewards_address,
        &protocol.multisig_address,
    );

    // rewards split evenly amongst all workers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(workers.len() as u64)
        * Uint128::from(2u64);

    for worker in workers {
        let balance = protocol
            .app
            .wrap()
            .query_balance(worker.addr, test_utils::AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}
