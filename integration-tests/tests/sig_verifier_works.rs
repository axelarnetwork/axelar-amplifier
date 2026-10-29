use std::collections::HashMap;

use axelar_wasm_std::{nonempty, Threshold};
use coordinator::msg::ExecuteMsg as CoordinatorExecuteMsg;
use cosmwasm_std::{coins, Api, HexBinary, Uint64};
use integration_tests::chain_codec_contract::ChainCodecContract;
use integration_tests::contract::Contract;
use integration_tests::failing_sig_verifier::FailingSigVerifier;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::PublicKey;
use multisig_prover_api::msg::ConstructProofMsg;
use rewards::PoolId;
use router_api::{chain_name, cosmos_addr};

use crate::test_utils::{
    create_new_verifiers_vec, register_service, register_verifiers, setup_protocol,
    AXL_DENOMINATION, ETHEREUM,
};

pub mod test_utils;

#[test]
fn sig_verifier_called() {
    let mut protocol = setup_protocol("validators".try_into().unwrap());
    let chain_name = chain_name!(ETHEREUM);
    let verifiers = create_new_verifiers_vec(
        vec![chain_name.clone()],
        vec![("verifier1".to_string(), 0), ("verifier2".to_string(), 1)],
    );

    let min_verifier_bond = nonempty::Uint128::try_from(100).unwrap();
    let unbonding_period_days = 10;
    register_service(&mut protocol, min_verifier_bond, unbonding_period_days);

    register_verifiers(&mut protocol, &verifiers, min_verifier_bond);

    let sig_verifier = FailingSigVerifier::instantiate_contract(&mut protocol.app);

    let chain_codec = ChainCodecContract::instantiate_contract(&mut protocol);

    let voting_verifier = VotingVerifierContract::instantiate_contract(
        &mut protocol,
        Threshold::try_from((3, 4)).unwrap().try_into().unwrap(),
        chain_name.clone(),
        &chain_codec.contract_addr,
    );

    let gateway = GatewayContract::instantiate_contract(
        &mut protocol.app,
        protocol.router.contract_address().clone(),
        voting_verifier.contract_addr.clone(),
    );

    let multisig_prover_admin = protocol
        .app
        .api()
        .addr_make(format!("{}_prover_admin", chain_name).as_str());
    let multisig_prover = MultisigProverContract::instantiate_contract(
        &mut protocol,
        multisig_prover_admin.clone(),
        gateway.contract_addr.clone(),
        voting_verifier.contract_addr.clone(),
        chain_codec.contract_addr.clone(),
        chain_name.to_string(),
        Some(sig_verifier.contract_addr.clone()),
        [0; 32],
        false,
        false,
    );

    let response = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &CoordinatorExecuteMsg::RegisterChain {
            chain_name: chain_name.clone(),
            prover_address: multisig_prover.contract_addr.to_string(),
            gateway_address: gateway.contract_addr.to_string(),
            voting_verifier_address: voting_verifier.contract_addr.to_string(),
        },
    );
    assert!(response.is_ok());

    let response = multisig_prover.execute(
        &mut protocol.app,
        multisig_prover_admin,
        &multisig_prover_api::msg::ExecuteMsg::UpdateVerifierSet,
    );
    assert!(response.is_ok());

    let response = protocol.multisig.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCallers {
            contracts: vec![(
                multisig_prover.contract_addr.to_string(),
                chain_name.clone(),
            )]
            .into_iter()
            .collect(),
        },
    );
    assert!(response.is_ok());

    // need to set up rewards pool

    let rewards_params = rewards::msg::Params {
        epoch_duration: nonempty::Uint64::try_from(10u64).unwrap(),
        rewards_per_epoch: nonempty::Uint128::try_from(100u128).unwrap(),
        participation_threshold: (1, 2).try_into().unwrap(),
    };

    let response = protocol.rewards.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &rewards::msg::ExecuteMsg::CreatePool {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: voting_verifier.contract_addr.to_string(),
            },
            params: rewards_params.clone(),
        },
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &rewards::msg::ExecuteMsg::CreatePool {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: protocol.multisig.contract_addr.to_string(),
            },
            params: rewards_params,
        },
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: voting_verifier.contract_addr.to_string(),
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
                contract: protocol.multisig.contract_addr.to_string(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    // cause signing session to start using ConstructProof
    let response = multisig_prover
        .execute(
            &mut protocol.app,
            cosmos_addr!("anyone"),
            &multisig_prover_api::msg::ExecuteMsg::ConstructProof(ConstructProofMsg::Messages(
                vec![],
            )),
        )
        .unwrap();

    // extract signing event data for next call
    let signing_event = response
        .events
        .iter()
        .find(|e| e.ty == "wasm-signing_started")
        .unwrap();
    let session_id: u64 = signing_event
        .attributes
        .iter()
        .find(|a| a.key == "session_id")
        .unwrap()
        .value
        .parse()
        .unwrap();
    let pub_keys = serde_json::from_str::<HashMap<String, PublicKey>>(
        &signing_event
            .attributes
            .iter()
            .find(|a| a.key == "pub_keys")
            .unwrap()
            .value,
    )
    .unwrap();

    let signer = protocol
        .app
        .api()
        .addr_validate(pub_keys.keys().next().unwrap())
        .unwrap();

    // submit signature
    let response = protocol
        .multisig
        .execute(
            &mut protocol.app,
            signer,
            &multisig::msg::ExecuteMsg::SubmitSignature {
                session_id: Uint64::new(session_id),
                signature: HexBinary::from(vec![0; 64]), // any value is fine, we just want to ensure the verifier is called
            },
        )
        .unwrap_err();

    assert!(response
        .to_string()
        .contains("signature verifier is having a bad day"));
}
