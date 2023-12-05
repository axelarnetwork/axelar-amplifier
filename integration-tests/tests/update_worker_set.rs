use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::{Addr, HexBinary, Uint128};


use test_utils::{Chain, Protocol, Worker};
mod test_utils;

fn setup_test_case() -> (Protocol, Chain, Vec<Worker>) {
    let mut protocol = test_utils::setup_protocol("validators".to_string().try_into().unwrap());
    let chains: Vec<connection_router::state::ChainName> =
        vec!["Ethereum".to_string().try_into().unwrap()];

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

    let ethereum = test_utils::setup_chain(&mut protocol, chains.get(0).unwrap().clone());
    (protocol, ethereum, workers)
}

#[test]
fn worker_set_can_be_initialized_and_then_updated() {
    let (mut protocol, ethereum, workers) = setup_test_case();

    // FLOW:
    // 1. Initialize worker set using UpdateWorkerSet. How do I test this completed?
    // 2. VotingVerifier::ConfirmWorkerSet, voting, and then MultisigProver::ConfirmWorkerSet which calls RegisterWorkerSet
    // 3. Register a new set of Workers to registry
    // 4. Call ConstructProof again
    // 5. ConstructProof will start a signing session to sign the new WorkerSet using the original WorkerSet
    // 6. Get Proof
    // 7. VotingVerifier::ConfirmWorkerSet
    // 8. Vote in Poll
    // 9. End Poll
    // 10. MultisigProver::ConfirmWorkerSet which calls RegisterWorkerSet

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol.app,
        &ethereum.multisig_prover_address,
        &protocol.multisig_address,
        &[],
        &workers,
    );

    test_utils::update_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );
}

#[test]
fn test_errors() {
    todo!()
}
