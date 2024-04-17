use axelar_wasm_std::{
    nonempty,
    voting::{PollId, Vote},
    Participant, Threshold,
};
use connection_router_api::{Address, ChainName, CrossChainId, GatewayDirection, Message};
use cosmwasm_std::{
    coins, Addr, Attribute, BlockInfo, Event, HexBinary, StdError, Uint128, Uint256, Uint64,
};
use cw_multi_test::{App, AppResponse, Executor};

use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::monitoring_contract::MonitoringContract;
use integration_tests::multisig_contract::MultisigContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::rewards_contract::RewardsContract;
use integration_tests::service_registry_contract::ServiceRegistryContract;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use integration_tests::{connection_router_contract::ConnectionRouterContract, protocol::Protocol};

use k256::ecdsa;
use sha3::{Digest, Keccak256};

use multisig::{
    key::{KeyType, PublicKey},
    worker_set::WorkerSet,
};
use multisig_prover::encoding::{make_operators, Encoder};
use rewards::state::PoolId;
use service_registry::msg::ExecuteMsg;
use tofn::ecdsa::KeyPair;

pub const AXL_DENOMINATION: &str = "uaxl";

pub const SIGNATURE_BLOCK_EXPIRY: u64 = 100;

fn get_event_attribute<'a>(
    events: &'a [Event],
    event_type: &str,
    attribute_name: &str,
) -> Option<&'a Attribute> {
    events
        .iter()
        .find(|ev| ev.ty == event_type)?
        .attributes
        .iter()
        .find(|attribute| attribute.key == attribute_name)
}

type PollExpiryBlock = u64;

pub fn verify_messages(
    app: &mut App,
    gateway: &GatewayContract,
    msgs: &[Message],
) -> (PollId, PollExpiryBlock) {
    let response = gateway.execute(
        app,
        Addr::unchecked("relayer"),
        &gateway_api::msg::ExecuteMsg::VerifyMessages(msgs.to_vec()),
    );
    assert!(response.is_ok());

    let response = response.unwrap();

    let poll_id = get_event_attribute(&response.events, "wasm-messages_poll_started", "poll_id")
        .map(|attr| serde_json::from_str(&attr.value).unwrap())
        .expect("couldn't get poll_id");
    let expiry = get_event_attribute(&response.events, "wasm-messages_poll_started", "expires_at")
        .map(|attr| attr.value.as_str().parse().unwrap())
        .expect("couldn't get poll expiry");
    (poll_id, expiry)
}

pub fn route_messages(app: &mut App, gateway: &GatewayContract, msgs: &[Message]) {
    let response = gateway.execute(
        app,
        Addr::unchecked("relayer"),
        &gateway_api::msg::ExecuteMsg::RouteMessages(msgs.to_vec()),
    );
    assert!(response.is_ok());
}

pub fn freeze_chain(
    app: &mut App,
    router: &ConnectionRouterContract,
    chain_name: &ChainName,
    direction: GatewayDirection,
    admin: &Addr,
) {
    let response = router.execute(
        app,
        admin.clone(),
        &connection_router_api::msg::ExecuteMsg::FreezeChain {
            chain: chain_name.clone(),
            direction,
        },
    );
    assert!(response.is_ok(), "{:?}", response);
}

pub fn unfreeze_chain(
    app: &mut App,
    router: &ConnectionRouterContract,
    chain_name: &ChainName,
    direction: GatewayDirection,
    admin: &Addr,
) {
    let response = router.execute(
        app,
        admin.clone(),
        &connection_router_api::msg::ExecuteMsg::UnfreezeChain {
            chain: chain_name.clone(),
            direction,
        },
    );
    assert!(response.is_ok(), "{:?}", response);
}

pub fn upgrade_gateway(
    app: &mut App,
    router: &ConnectionRouterContract,
    governance: &Addr,
    chain_name: &ChainName,
    contract_address: Address,
) {
    let response = router.execute(
        app,
        governance.clone(),
        &connection_router_api::msg::ExecuteMsg::UpgradeGateway {
            chain: chain_name.clone(),
            contract_address,
        },
    );
    assert!(response.is_ok(), "{:?}", response);
}

pub fn vote_success_for_all_messages(
    app: &mut App,
    voting_verifier: &VotingVerifierContract,
    messages: &[Message],
    workers: &[Worker],
    poll_id: PollId,
) {
    for worker in workers {
        let response = voting_verifier.execute(
            app,
            worker.addr.clone(),
            &voting_verifier::msg::ExecuteMsg::Vote {
                poll_id,
                votes: vec![Vote::SucceededOnChain; messages.len()],
            },
        );
        assert!(response.is_ok());
    }
}

pub fn vote_true_for_worker_set(
    app: &mut App,
    voting_verifier: &VotingVerifierContract,
    workers: &Vec<Worker>,
    poll_id: PollId,
) {
    for worker in workers {
        let response = voting_verifier.execute(
            app,
            worker.addr.clone(),
            &voting_verifier::msg::ExecuteMsg::Vote {
                poll_id,
                votes: vec![Vote::SucceededOnChain; 1],
            },
        );
        assert!(response.is_ok())
    }
}

/// Ends the poll. Be sure the current block height has advanced at least to the poll expiration, else this will fail
pub fn end_poll(app: &mut App, voting_verifier: &VotingVerifierContract, poll_id: PollId) {
    let response = voting_verifier.execute(
        app,
        Addr::unchecked("relayer"),
        &voting_verifier::msg::ExecuteMsg::EndPoll { poll_id },
    );
    assert!(response.is_ok());
}

pub fn construct_proof_and_sign(
    protocol: &mut Protocol,
    multisig_prover: &MultisigProverContract,
    messages: &[Message],
    workers: &Vec<Worker>,
) -> Uint64 {
    let response = multisig_prover.execute(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &multisig_prover::msg::ExecuteMsg::ConstructProof {
            message_ids: messages.iter().map(|msg| msg.cc_id.clone()).collect(),
        },
    );
    assert!(response.is_ok());

    sign_proof(protocol, workers, response.unwrap())
}

pub fn get_multisig_session_id(response: AppResponse) -> Uint64 {
    get_event_attribute(&response.events, "wasm-signing_started", "session_id")
        .map(|attr| attr.value.as_str().try_into().unwrap())
        .expect("couldn't get session_id")
}

pub fn sign_proof(protocol: &mut Protocol, workers: &Vec<Worker>, response: AppResponse) -> Uint64 {
    let msg_to_sign = get_event_attribute(&response.events, "wasm-signing_started", "msg")
        .map(|attr| attr.value.clone())
        .expect("couldn't find message to sign");
    let session_id = get_multisig_session_id(response);

    for worker in workers {
        let signature = tofn::ecdsa::sign(
            worker.key_pair.signing_key(),
            &HexBinary::from_hex(&msg_to_sign)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let sig = ecdsa::Signature::from_der(&signature).unwrap();

        let response = protocol.multisig.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &multisig::msg::ExecuteMsg::SubmitSignature {
                session_id,
                signature: HexBinary::from(sig.to_vec()),
            },
        );
        assert!(response.is_ok());
    }

    session_id
}

pub fn register_service(protocol: &mut Protocol, min_worker_bond: Uint128) {
    let response = protocol.service_registry.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ExecuteMsg::RegisterService {
            service_name: protocol.service_name.to_string(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(response.is_ok());
}

pub fn get_messages_from_gateway(
    app: &mut App,
    gateway: &GatewayContract,
    message_ids: &[CrossChainId],
) -> Vec<Message> {
    let query_response: Result<Vec<Message>, StdError> = gateway.query(
        app,
        &gateway_api::msg::QueryMsg::GetOutgoingMessages {
            message_ids: message_ids.to_owned(),
        },
    );
    assert!(query_response.is_ok());

    query_response.unwrap()
}

pub fn get_proof(
    app: &mut App,
    multisig_prover: &MultisigProverContract,
    multisig_session_id: &Uint64,
) -> multisig_prover::msg::GetProofResponse {
    let query_response: Result<multisig_prover::msg::GetProofResponse, StdError> = multisig_prover
        .query(
            app,
            &multisig_prover::msg::QueryMsg::GetProof {
                multisig_session_id: *multisig_session_id,
            },
        );
    assert!(query_response.is_ok());

    query_response.unwrap()
}

pub fn get_worker_set(
    app: &mut App,
    multisig_prover_contract: &MultisigProverContract,
) -> WorkerSet {
    let query_response: Result<WorkerSet, StdError> =
        multisig_prover_contract.query(app, &multisig_prover::msg::QueryMsg::GetWorkerSet);
    assert!(query_response.is_ok());

    query_response.unwrap()
}

#[allow(clippy::arithmetic_side_effects)]
pub fn advance_height(app: &mut App, increment: u64) {
    let cur_block = app.block_info();
    app.set_block(BlockInfo {
        height: cur_block.height + increment,
        ..cur_block
    });
}

pub fn advance_at_least_to_height(app: &mut App, desired_height: u64) {
    let cur_block = app.block_info();
    if app.block_info().height < desired_height {
        app.set_block(BlockInfo {
            height: desired_height,
            ..cur_block
        });
    }
}

pub fn distribute_rewards(protocol: &mut Protocol, chain_name: &ChainName, contract_address: Addr) {
    let response = protocol.rewards.execute(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &rewards::msg::ExecuteMsg::DistributeRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: contract_address,
            },
            epoch_count: None,
        },
    );
    assert!(response.is_ok());
}

pub fn setup_protocol(service_name: nonempty::String) -> Protocol {
    let genesis = Addr::unchecked("genesis");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &genesis, coins(u128::MAX, AXL_DENOMINATION))
            .unwrap()
    });
    let router_admin_address = Addr::unchecked("admin");
    let governance_address = Addr::unchecked("governance");
    let nexus_gateway = Addr::unchecked("nexus_gateway");

    let connection_router = ConnectionRouterContract::instantiate_contract(
        &mut app,
        router_admin_address.clone(),
        governance_address.clone(),
        nexus_gateway.clone(),
    );

    let rewards_params = rewards::msg::Params {
        epoch_duration: nonempty::Uint64::try_from(10u64).unwrap(),
        rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
        participation_threshold: (1, 2).try_into().unwrap(),
    };
    let rewards = RewardsContract::instantiate_contract(
        &mut app,
        governance_address.clone(),
        AXL_DENOMINATION.to_string(),
        rewards_params.clone(),
    );

    let multisig = MultisigContract::instantiate_contract(
        &mut app,
        governance_address.clone(),
        rewards.contract_addr.clone(),
        SIGNATURE_BLOCK_EXPIRY,
    );

    let monitoring = MonitoringContract::instantiate_contract(&mut app, governance_address.clone());

    let service_registry =
        ServiceRegistryContract::instantiate_contract(&mut app, governance_address.clone());

    Protocol {
        genesis_address: genesis,
        governance_address,
        connection_router,
        router_admin_address,
        multisig,
        monitoring,
        service_registry,
        service_name,
        rewards,
        rewards_params,
        app,
    }
}

// generates a key pair using the given seed. The key pair should not be used outside of testing
pub fn generate_key(seed: u32) -> KeyPair {
    let seed_bytes = seed.to_be_bytes();
    let mut result = [0; 64];
    result[0..seed_bytes.len()].copy_from_slice(seed_bytes.as_slice());
    let secret_recovery_key = result.as_slice().try_into().unwrap();
    tofn::ecdsa::keygen(&secret_recovery_key, b"tofn nonce").unwrap()
}

pub struct Worker {
    pub addr: Addr,
    pub supported_chains: Vec<ChainName>,
    pub key_pair: KeyPair,
}

pub fn register_workers(protocol: &mut Protocol, workers: &Vec<Worker>, min_worker_bond: Uint128) {
    let response = protocol.service_registry.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: workers
                .iter()
                .map(|worker| worker.addr.to_string())
                .collect(),
            service_name: protocol.service_name.to_string(),
        },
    );
    assert!(response.is_ok());

    for worker in workers {
        let response = protocol.app.send_tokens(
            protocol.genesis_address.clone(),
            worker.addr.clone(),
            &coins(min_worker_bond.u128(), AXL_DENOMINATION),
        );
        assert!(response.is_ok());

        let response = protocol.service_registry.execute_with_funds(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::BondWorker {
                service_name: protocol.service_name.to_string(),
            },
            &coins(min_worker_bond.u128(), AXL_DENOMINATION),
        );
        assert!(response.is_ok());

        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::RegisterChainSupport {
                service_name: protocol.service_name.to_string(),
                chains: worker.supported_chains.clone(),
            },
        );
        assert!(response.is_ok());

        let address_hash = Keccak256::digest(worker.addr.as_bytes());

        let sig = tofn::ecdsa::sign(
            worker.key_pair.signing_key(),
            &address_hash.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let sig = ecdsa::Signature::from_der(&sig).unwrap();

        let response = protocol.multisig.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &multisig::msg::ExecuteMsg::RegisterPublicKey {
                public_key: PublicKey::Ecdsa(HexBinary::from(
                    worker.key_pair.encoded_verifying_key(),
                )),
                signed_sender_address: HexBinary::from(sig.to_vec()),
            },
        );
        assert!(response.is_ok());
    }
}

pub fn deregister_workers(protocol: &mut Protocol, workers: &Vec<Worker>) {
    let response = protocol.service_registry.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ExecuteMsg::UnauthorizeWorkers {
            workers: workers
                .iter()
                .map(|worker| worker.addr.to_string())
                .collect(),
            service_name: protocol.service_name.to_string(),
        },
    );
    assert!(response.is_ok());

    for worker in workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }
}

pub fn confirm_worker_set(
    app: &mut App,
    relayer_addr: Addr,
    multisig_prover: &MultisigProverContract,
) {
    let response = multisig_prover.execute(
        app,
        relayer_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::ConfirmWorkerSet,
    );
    assert!(response.is_ok());
}

fn get_worker_set_poll_id_and_expiry(response: AppResponse) -> (PollId, PollExpiryBlock) {
    let poll_id = get_event_attribute(&response.events, "wasm-worker_set_poll_started", "poll_id")
        .map(|attr| serde_json::from_str(&attr.value).unwrap())
        .expect("couldn't get poll_id");
    let expiry = get_event_attribute(
        &response.events,
        "wasm-worker_set_poll_started",
        "expires_at",
    )
    .map(|attr| attr.value.as_str().parse().unwrap())
    .expect("couldn't get poll expiry");
    (poll_id, expiry)
}

pub fn create_worker_set_poll(
    app: &mut App,
    relayer_addr: Addr,
    voting_verifier: &VotingVerifierContract,
    worker_set: WorkerSet,
) -> (PollId, PollExpiryBlock) {
    let response = voting_verifier.execute(
        app,
        relayer_addr.clone(),
        &voting_verifier::msg::ExecuteMsg::VerifyWorkerSet {
            message_id: "7477095de32cfca1522076e3581501ddc249c5796622d1194f0b7ef891769bdb-0"
                .parse()
                .unwrap(),
            new_operators: make_operators(worker_set.clone(), Encoder::Abi),
        },
    );
    assert!(response.is_ok());

    get_worker_set_poll_id_and_expiry(response.unwrap())
}

pub fn workers_to_worker_set(protocol: &mut Protocol, workers: &Vec<Worker>) -> WorkerSet {
    // get public keys
    let mut pub_keys = vec![];
    for worker in workers {
        let encoded_verifying_key =
            HexBinary::from(worker.key_pair.encoded_verifying_key().to_vec());
        let pub_key = PublicKey::try_from((KeyType::Ecdsa, encoded_verifying_key)).unwrap();
        pub_keys.push(pub_key);
    }

    // turn into participants
    let participants: Vec<Participant> = workers
        .iter()
        .map(|worker| Participant {
            address: worker.addr.clone(),
            weight: Uint256::one().try_into().unwrap(),
        })
        .collect();

    let total_weight = Uint256::from_u128(participants.len() as u128);

    let pubkeys_by_participant = participants.into_iter().zip(pub_keys).collect();

    WorkerSet::new(
        pubkeys_by_participant,
        total_weight.mul_ceil((2u64, 3u64)),
        protocol.app.block_info().height,
    )
}

pub fn create_new_workers_vec(
    chains: Vec<ChainName>,
    worker_details: Vec<(String, u32)>,
) -> Vec<Worker> {
    worker_details
        .into_iter()
        .map(|(name, seed)| Worker {
            addr: Addr::unchecked(name),
            supported_chains: chains.clone(),
            key_pair: generate_key(seed),
        })
        .collect()
}

pub fn update_registry_and_construct_worker_set_update_proof(
    protocol: &mut Protocol,
    new_workers: &Vec<Worker>,
    workers_to_remove: &Vec<Worker>,
    current_workers: &Vec<Worker>,
    chain_multisig_prover: &MultisigProverContract,
    min_worker_bond: Uint128,
) -> Uint64 {
    // Register new workers
    register_workers(protocol, new_workers, min_worker_bond);

    // Deregister old workers
    deregister_workers(protocol, workers_to_remove);

    let response = chain_multisig_prover.execute(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );

    sign_proof(protocol, current_workers, response.unwrap())
}

pub fn execute_worker_set_poll(
    protocol: &mut Protocol,
    relayer_addr: &Addr,
    voting_verifier: &VotingVerifierContract,
    new_workers: &Vec<Worker>,
) {
    // Create worker set
    let new_worker_set = workers_to_worker_set(protocol, new_workers);

    // Create worker set poll
    let (poll_id, expiry) = create_worker_set_poll(
        &mut protocol.app,
        relayer_addr.clone(),
        voting_verifier,
        new_worker_set.clone(),
    );

    // Vote for the worker set
    vote_true_for_worker_set(&mut protocol.app, voting_verifier, new_workers, poll_id);

    // Advance to expiration height
    advance_at_least_to_height(&mut protocol.app, expiry);

    // End the poll
    end_poll(&mut protocol.app, voting_verifier, poll_id);
}

#[derive(Clone)]
pub struct Chain {
    pub gateway: GatewayContract,
    pub voting_verifier: VotingVerifierContract,
    pub multisig_prover: MultisigProverContract,
    pub chain_name: ChainName,
}

pub fn setup_chain(protocol: &mut Protocol, chain_name: ChainName) -> Chain {
    let voting_verifier = VotingVerifierContract::instantiate_contract(
        protocol,
        "doesn't matter".to_string().try_into().unwrap(),
        Threshold::try_from((9, 10)).unwrap().try_into().unwrap(),
        chain_name.clone(),
    );

    let gateway = GatewayContract::instantiate_contract(
        &mut protocol.app,
        protocol.connection_router.contract_address().clone(),
        voting_verifier.contract_addr.clone(),
    );

    let multisig_prover_admin = Addr::unchecked(chain_name.to_string() + "prover_admin");
    let multisig_prover = MultisigProverContract::instantiate_contract(
        protocol,
        multisig_prover_admin.clone(),
        gateway.contract_addr.clone(),
        voting_verifier.contract_addr.clone(),
        chain_name.to_string(),
    );

    let response = multisig_prover.execute(
        &mut protocol.app,
        multisig_prover_admin,
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );
    assert!(response.is_ok());

    let response = protocol.multisig.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCaller {
            contract_address: multisig_prover.contract_addr.clone(),
        },
    );
    assert!(response.is_ok());

    let response = protocol.connection_router.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &connection_router_api::msg::ExecuteMsg::RegisterChain {
            chain: chain_name.clone(),
            gateway_address: gateway.contract_addr.to_string().try_into().unwrap(),
            msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
        },
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: voting_verifier.contract_addr.clone(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: protocol.multisig.contract_addr.clone(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    Chain {
        gateway,
        voting_verifier,
        multisig_prover,
        chain_name,
    }
}

// Creates an instance of Axelar Amplifier with an initial worker set registered, and returns the instance, the chains, the workers, and the minimum worker bond.
pub fn setup_test_case() -> (Protocol, Chain, Chain, Vec<Worker>, Uint128) {
    let mut protocol = setup_protocol("validators".to_string().try_into().unwrap());
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let workers = vec![
        Worker {
            addr: Addr::unchecked("worker1"),
            supported_chains: chains.clone(),
            key_pair: generate_key(0),
        },
        Worker {
            addr: Addr::unchecked("worker2"),
            supported_chains: chains.clone(),
            key_pair: generate_key(1),
        },
    ];
    let min_worker_bond = Uint128::new(100);
    register_service(&mut protocol, min_worker_bond);

    register_workers(&mut protocol, &workers, min_worker_bond);
    let chain1 = setup_chain(&mut protocol, chains.first().unwrap().clone());
    let chain2 = setup_chain(&mut protocol, chains.get(1).unwrap().clone());
    (protocol, chain1, chain2, workers, min_worker_bond)
}

pub fn assert_contract_err_strings_equal(
    actual: impl Into<axelar_wasm_std::ContractError>,
    expected: impl Into<axelar_wasm_std::ContractError>,
) {
    assert_eq!(actual.into().to_string(), expected.into().to_string());
}
