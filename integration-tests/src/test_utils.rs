use axelar_wasm_std::{nonempty, voting::PollID};
use connection_router::state::{ChainName, CrossChainId, Message};
use cosmwasm_std::{
    coins, Addr, Attribute, Binary, BlockInfo, Deps, Env, Event, HexBinary, StdResult, Uint128,
    Uint256, Uint64,
};
use cw_multi_test::{App, ContractWrapper, Executor};

use k256::ecdsa;
use multisig::key::PublicKey;
use tofn::ecdsa::KeyPair;

pub const AXL_DENOMINATION: &str = "uaxl";

fn get_event_attribute<'a>(
    events: &'a [Event],
    event_type: &str,
    attribute_key: &str,
) -> Option<&'a Attribute> {
    if let Some(event) = events.iter().find(|ev| ev.ty == event_type) {
        return event
            .attributes
            .iter()
            .find(|attr| attr.key == attribute_key);
    }
    None
}

pub fn verify_messages(app: &mut App, gateway_address: &Addr, msgs: &[Message]) -> (PollID, u64) {
    let response = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &gateway::msg::ExecuteMsg::VerifyMessages(msgs.to_vec()),
            &[],
        )
        .unwrap();

    let poll_id = get_event_attribute(&response.events, "wasm-messages_poll_started", "poll_id")
        .map(|attr| serde_json::from_str(&attr.value).unwrap())
        .expect("couldn't get poll_id");
    let expiry = get_event_attribute(&response.events, "wasm-messages_poll_started", "expires_at")
        .map(|attr| attr.value.as_str().parse().unwrap())
        .expect("couldn't get poll expiry");
    (poll_id, expiry)
}

pub fn route_messages(app: &mut App, gateway_address: &Addr, msgs: &[Message]) {
    app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &gateway::msg::ExecuteMsg::RouteMessages(msgs.to_vec()),
        &[],
    )
    .unwrap();
}

pub fn vote_true_for_all(
    app: &mut App,
    workers: &Vec<Worker>,
    voting_verifier_address: &Addr,
    poll_id: PollID,
    msgs: &Vec<Message>,
) {
    for worker in workers {
        app.execute_contract(
            worker.addr.clone(),
            voting_verifier_address.clone(),
            &voting_verifier::msg::ExecuteMsg::Vote {
                poll_id,
                votes: vec![true; msgs.len()],
            },
            &[],
        )
        .unwrap();
    }
}

/// End the poll. Advances the current height to expiry if necessary
pub fn end_poll(app: &mut App, voting_verifier_address: &Addr, poll_id: PollID, expiry: u64) {
    if app.block_info().height < expiry {
        advance_to_height(app, expiry);
    }
    app.execute_contract(
        Addr::unchecked("relayer"),
        voting_verifier_address.clone(),
        &voting_verifier::msg::ExecuteMsg::EndPoll { poll_id },
        &[],
    )
    .unwrap();
}

pub fn construct_proof_and_sign(
    app: &mut App,
    messages: &[Message],
    multisig_prover_address: &Addr,
    multisig_address: &Addr,
    workers: &Vec<Worker>,
) -> Uint64 {
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            multisig_prover_address.clone(),
            &multisig_prover::msg::ExecuteMsg::ConstructProof {
                message_ids: messages.iter().map(|msg| msg.cc_id.to_string()).collect(),
            },
            &[],
        )
        .unwrap();

    let msg_to_sign = get_event_attribute(&res.events, "wasm-signing_started", "msg")
        .map(|attr| attr.value.clone())
        .expect("couldn't find message to sign");
    let session_id: Uint64 = get_event_attribute(&res.events, "wasm-signing_started", "session_id")
        .map(|attr| attr.value.as_str().try_into().unwrap())
        .expect("couldn't get session_id");

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

        app.execute_contract(
            worker.addr.clone(),
            multisig_address.clone(),
            &multisig::msg::ExecuteMsg::SubmitSignature {
                session_id,
                signature: HexBinary::from(sig.to_vec()),
            },
            &[],
        )
        .unwrap();
    }
    session_id
}

pub fn get_messages_from_gateway(
    app: &mut App,
    gateway_address: &Addr,
    message_ids: &[CrossChainId],
) -> Vec<Message> {
    app.wrap()
        .query_wasm_smart(
            gateway_address,
            &gateway::msg::QueryMsg::GetMessages {
                message_ids: message_ids.to_owned(),
            },
        )
        .unwrap()
}

pub fn get_proof(
    app: &mut App,
    multisig_prover_address: &Addr,
    multisig_session_id: &Uint64,
) -> multisig_prover::msg::GetProofResponse {
    app.wrap()
        .query_wasm_smart(
            multisig_prover_address,
            &multisig_prover::msg::QueryMsg::GetProof {
                multisig_session_id: *multisig_session_id,
            },
        )
        .unwrap()
}

pub fn advance_height(app: &mut App, num_blocks: u64) {
    let old_block = app.block_info();
    app.set_block(BlockInfo {
        height: old_block.height + num_blocks,
        ..old_block
    });
}

pub fn advance_to_height(app: &mut App, desired_height: u64) {
    let cur_block = app.block_info();
    assert!(cur_block.height < desired_height);
    let diff = desired_height - cur_block.height;
    advance_height(app, diff);
}

pub fn distribute_rewards(app: &mut App, rewards_address: &Addr, contract_address: &Addr) {
    app.execute_contract(
        Addr::unchecked("relayer"),
        rewards_address.clone(),
        &rewards::msg::ExecuteMsg::DistributeRewards {
            contract_address: contract_address.to_string(),
            epoch_count: None,
        },
        &[],
    )
    .unwrap();
}

#[allow(dead_code)]
pub struct Protocol {
    pub genesis_address: Addr, // holds u128::max coins, can use to send coins to other addresses
    pub governance_address: Addr,
    pub router_address: Addr,
    pub router_admin_address: Addr,
    pub multisig_address: Addr,
    pub service_registry_address: Addr,
    pub service_name: nonempty::String,
    pub rewards_address: Addr,
    pub rewards_params: rewards::msg::Params,
    pub app: App,
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

    let router_address = instantiate_connection_router(
        &mut app,
        connection_router::msg::InstantiateMsg {
            admin_address: router_admin_address.to_string(),
            governance_address: governance_address.to_string(),
        },
    );

    let rewards_params = rewards::msg::Params {
        epoch_duration: nonempty::Uint64::try_from(10u64).unwrap(),
        rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
        participation_threshold: (1, 2).try_into().unwrap(),
    };
    let rewards_address = instantiate_rewards(
        &mut app,
        rewards::msg::InstantiateMsg {
            governance_address: governance_address.to_string(),
            rewards_denom: AXL_DENOMINATION.to_string(),
            params: rewards_params.clone(),
        },
    );
    let multisig_address = instantiate_multisig(
        &mut app,
        multisig::msg::InstantiateMsg {
            rewards_address: rewards_address.to_string(),
            governance_address: governance_address.to_string(),
            grace_period: 2,
        },
    );
    let service_registry_address = instantiate_service_registry(
        &mut app,
        service_registry::msg::InstantiateMsg {
            governance_account: governance_address.to_string(),
        },
    );
    app.execute_contract(
        genesis.clone(),
        rewards_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            contract_address: multisig_address.to_string(),
        },
        &coins(1000, AXL_DENOMINATION),
    )
    .unwrap();

    Protocol {
        genesis_address: genesis,
        governance_address,
        router_address,
        router_admin_address,
        multisig_address,
        service_registry_address,
        service_name,
        rewards_address,
        rewards_params,
        app,
    }
}

// return the all-zero array with the first bytes set to the bytes of `index`
pub fn generate_key(seed: u32) -> KeyPair {
    let index_bytes = seed.to_be_bytes();
    let mut result = [0; 64];
    result[0..index_bytes.len()].copy_from_slice(index_bytes.as_slice());
    let secret_recovery_key = result.as_slice().try_into().unwrap();
    tofn::ecdsa::keygen(&secret_recovery_key, b"tofn nonce").unwrap()
}

pub struct Worker {
    pub addr: Addr,
    pub supported_chains: Vec<ChainName>,
    pub key_pair: KeyPair,
}

pub fn register_workers(
    app: &mut App,
    service_registry: Addr,
    multisig: Addr,
    service_name: nonempty::String,
    governance_addr: Addr,
    workers: &Vec<Worker>,
    genesis: Addr,
) {
    let min_worker_bond = Uint128::new(100);
    app.execute_contract(
        governance_addr.clone(),
        service_registry.clone(),
        &service_registry::msg::ExecuteMsg::RegisterService {
            service_name: service_name.to_string(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
        &[],
    )
    .unwrap();

    app.execute_contract(
        governance_addr,
        service_registry.clone(),
        &service_registry::msg::ExecuteMsg::AuthorizeWorkers {
            workers: workers
                .iter()
                .map(|worker| worker.addr.to_string())
                .collect(),
            service_name: service_name.to_string(),
        },
        &[],
    )
    .unwrap();

    for worker in workers {
        app.send_tokens(
            genesis.clone(),
            worker.addr.clone(),
            &coins(min_worker_bond.u128(), AXL_DENOMINATION),
        )
        .unwrap();
        app.execute_contract(
            worker.addr.clone(),
            service_registry.clone(),
            &service_registry::msg::ExecuteMsg::BondWorker {
                service_name: service_name.to_string(),
            },
            &coins(min_worker_bond.u128(), AXL_DENOMINATION),
        )
        .unwrap();

        app.execute_contract(
            worker.addr.clone(),
            service_registry.clone(),
            &service_registry::msg::ExecuteMsg::DeclareChainSupport {
                service_name: service_name.to_string(),
                chains: worker.supported_chains.clone(),
            },
            &[],
        )
        .unwrap();

        app.execute_contract(
            worker.addr.clone(),
            multisig.clone(),
            &multisig::msg::ExecuteMsg::RegisterPublicKey {
                public_key: PublicKey::Ecdsa(HexBinary::from(
                    worker.key_pair.encoded_verifying_key(),
                )),
            },
            &[],
        )
        .unwrap();
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Chain {
    pub gateway_address: Addr,
    pub voting_verifier_address: Addr,
    pub multisig_prover_address: Addr,
    pub chain_name: ChainName,
}

pub fn setup_chain(protocol: &mut Protocol, chain_name: ChainName) -> Chain {
    let voting_verifier_address = instantiate_voting_verifier(
        &mut protocol.app,
        voting_verifier::msg::InstantiateMsg {
            service_registry_address: protocol
                .service_registry_address
                .to_string()
                .try_into()
                .unwrap(),
            service_name: protocol.service_name.clone(),
            source_gateway_address: "doesn't matter".to_string().try_into().unwrap(),
            voting_threshold: (9, 10).try_into().unwrap(),
            block_expiry: 10,
            confirmation_height: 5,
            source_chain: chain_name.clone(),
            rewards_address: protocol.rewards_address.to_string(),
        },
    );
    let gateway_address = instantiate_gateway(
        &mut protocol.app,
        gateway::msg::InstantiateMsg {
            router_address: protocol.router_address.to_string(),
            verifier_address: voting_verifier_address.to_string(),
        },
    );
    let multisig_prover_address = instantiate_multisig_prover(
        &mut protocol.app,
        multisig_prover::msg::InstantiateMsg {
            admin_address: Addr::unchecked("doesn't matter").to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: protocol.multisig_address.to_string(),
            service_registry_address: protocol.service_registry_address.to_string(),
            voting_verifier_address: voting_verifier_address.to_string(),
            destination_chain_id: Uint256::zero(),
            signing_threshold: (2, 3).try_into().unwrap(),
            service_name: protocol.service_name.to_string(),
            chain_name: chain_name.to_string(),
            worker_set_diff_threshold: 1,
            encoder: multisig_prover::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
        },
    );
    protocol
        .app
        .execute_contract(
            Addr::unchecked("doesn't matter"),
            multisig_prover_address.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();
    protocol
        .app
        .execute_contract(
            protocol.governance_address.clone(),
            protocol.multisig_address.clone(),
            &multisig::msg::ExecuteMsg::AuthorizeCaller {
                contract_address: multisig_prover_address.clone(),
            },
            &[],
        )
        .unwrap();

    protocol
        .app
        .execute_contract(
            protocol.governance_address.clone(),
            protocol.router_address.clone(),
            &connection_router::msg::ExecuteMsg::RegisterChain {
                chain: chain_name.clone(),
                gateway_address: gateway_address.to_string(),
            },
            &[],
        )
        .unwrap();

    protocol
        .app
        .execute_contract(
            protocol.genesis_address.clone(),
            protocol.rewards_address.clone(),
            &rewards::msg::ExecuteMsg::AddRewards {
                contract_address: voting_verifier_address.to_string(),
            },
            &coins(1000, AXL_DENOMINATION),
        )
        .unwrap();

    Chain {
        gateway_address,
        voting_verifier_address,
        multisig_prover_address,
        chain_name,
    }
}

pub fn instantiate_connection_router(
    app: &mut App,
    instantiate_msg: connection_router::msg::InstantiateMsg,
) -> Addr {
    let code = ContractWrapper::new(
        connection_router::contract::execute,
        connection_router::contract::instantiate,
        connection_router::contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "connection_router",
        None,
    )
    .unwrap()
}

pub fn instantiate_multisig(app: &mut App, instantiate_msg: multisig::msg::InstantiateMsg) -> Addr {
    let code = ContractWrapper::new(
        multisig::contract::execute,
        multisig::contract::instantiate,
        multisig::contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "multisig",
        None,
    )
    .unwrap()
}

pub fn instantiate_rewards(app: &mut App, instantiate_msg: rewards::msg::InstantiateMsg) -> Addr {
    let code = ContractWrapper::new(
        rewards::contract::execute,
        rewards::contract::instantiate,
        |_: Deps, _: Env, _: rewards::msg::QueryMsg| -> StdResult<Binary> { todo!() },
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "rewards",
        None,
    )
    .unwrap()
}

pub fn instantiate_voting_verifier(
    app: &mut App,
    instantiate_msg: voting_verifier::msg::InstantiateMsg,
) -> Addr {
    let code = ContractWrapper::new(
        voting_verifier::contract::execute,
        voting_verifier::contract::instantiate,
        voting_verifier::contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "voting_verifier",
        None,
    )
    .unwrap()
}

pub fn instantiate_gateway(app: &mut App, instantiate_msg: gateway::msg::InstantiateMsg) -> Addr {
    let code = ContractWrapper::new(
        gateway::contract::execute,
        gateway::contract::instantiate,
        gateway::contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "gateway",
        None,
    )
    .unwrap()
}

pub fn instantiate_service_registry(
    app: &mut App,
    instantiate_msg: service_registry::msg::InstantiateMsg,
) -> Addr {
    let code = ContractWrapper::new(
        service_registry::contract::execute,
        service_registry::contract::instantiate,
        service_registry::contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "service_registry",
        None,
    )
    .unwrap()
}

pub fn instantiate_multisig_prover(
    app: &mut App,
    instantiate_msg: multisig_prover::msg::InstantiateMsg,
) -> Addr {
    let code = ContractWrapper::new(
        multisig_prover::contract::execute,
        multisig_prover::contract::instantiate,
        multisig_prover::contract::query,
    )
    .with_reply(multisig_prover::contract::reply);
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        Addr::unchecked("anyone"),
        &instantiate_msg,
        &[],
        "multisig_prover",
        None,
    )
    .unwrap()
}
