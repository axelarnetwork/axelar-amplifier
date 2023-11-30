use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::{Addr, HexBinary, Uint128};

use test_utils::{Chain, Protocol, Worker};
mod test_utils;
/// Tests that a single message can be routed fully through the protocol. Submits a message to the
/// gateway, votes on the poll, routes the message to the outgoing gateway, triggers signing at the prover
/// and signs via multisig. Also tests that rewards are distributed as expected for voting and signing.
#[test]
fn single_message_can_be_verified_and_routed_and_proven_and_rewards_are_distributed() {
    let (mut protocol, chain1, chain2, workers) = setup_test_case();

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
    test_utils::vote_true_for_all(
        &mut protocol.app,
        &chain1.voting_verifier_address,
        &msgs,
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
    assert_eq!(
        proof.message_ids,
        msg_ids
            .iter()
            .map(|msg_id| msg_id.to_string())
            .collect::<Vec<String>>()
    );

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

fn setup_test_case() -> (Protocol, Chain, Chain, Vec<Worker>) {
    let mut protocol = test_utils::setup_protocol("validators".to_string().try_into().unwrap());
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let workers = vec![
        Worker {
            addr: Addr::unchecked("worker1"),
            supported_chains: chains.clone(),
            key_pair: test_utils::generate_key(0),
        },
        Worker {
            addr: Addr::unchecked("worker2"),
            supported_chains: chains.clone(),
            key_pair: test_utils::generate_key(1),
        },
    ];
    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &workers,
        protocol.service_name.clone(),
    );
    let chain1 = test_utils::setup_chain(&mut protocol, chains.get(0).unwrap().clone());
    let chain2 = test_utils::setup_chain(&mut protocol, chains.get(1).unwrap().clone());
    (protocol, chain1, chain2, workers)
}
