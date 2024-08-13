use cosmwasm_std::{Addr, HexBinary, Uint128};
use integration_tests::contract::Contract;
use router_api::{CrossChainId, Message};

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
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &chain1.voting_verifier,
        &msgs,
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
