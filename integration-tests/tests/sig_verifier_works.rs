use std::collections::HashMap;
use std::num::NonZeroU64;

use axelar_wasm_std::Threshold;
use coordinator::msg::ExecuteMsg as CoordinatorExecuteMsg;
use cosmwasm_std::{Api, HexBinary, Uint64};
use integration_tests::chain_codec_contract::ChainCodecContract;
use integration_tests::contract::Contract;
use integration_tests::failing_sig_verifier::FailingSigVerifier;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::PublicKey;
use multisig_prover_api::msg::ConstructProofMsg;
use router_api::{chain_name, cosmos_addr};

pub mod test_utils;

#[test]
fn sig_verifier_called() {
    let test_utils::TestCase { mut protocol, .. } = test_utils::setup_test_case();

    let chain_name = chain_name!("ethereum");

    let sig_verifier = FailingSigVerifier::instantiate_contract(&mut protocol.app);

    let prover_address = protocol.app.init_modules(|_, api, storage| {
        protocol
            .address_generator
            // order is: chain codec, voting verifier, gateway, multisig prover, so 4 addresses ahead should be the prover address
            .future_address(api, storage, NonZeroU64::new(4).unwrap())
            .unwrap()
    });

    let chain_codec =
        ChainCodecContract::instantiate_contract(&mut protocol, prover_address.clone());

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

    let response = multisig_prover.execute(
        &mut protocol.app,
        multisig_prover_admin,
        &multisig_prover_api::msg::ExecuteMsg::UpdateVerifierSet,
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
