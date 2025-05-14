use axelar_wasm_std::{permission_control, Threshold};
use coordinator::msg::ExecuteMsg as CoordinatorExecuteMsg;
use cosmwasm_std::testing::MockApi;
use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use router_api::ChainName;

pub mod test_utils;

#[test]
fn only_prover_can_update_verifier_set_with_coordinator() {
    let test_utils::TestCase { mut protocol, .. } = test_utils::setup_test_case();

    let chain_name: ChainName = "ethereum".parse().unwrap();

    // New chain configuration where the coordinator has the wrong prover address
    let voting_verifier = VotingVerifierContract::instantiate_contract(
        &mut protocol,
        Threshold::try_from((3, 4)).unwrap().try_into().unwrap(),
        chain_name.clone(),
    );

    let gateway = GatewayContract::instantiate_contract(
        &mut protocol.app,
        protocol.router.contract_address().clone(),
        voting_verifier.contract_addr.clone(),
    );

    let multisig_prover_admin =
        MockApi::default().addr_make(format!("{}_prover_admin", chain_name).as_str());
    let multisig_prover = MultisigProverContract::instantiate_contract(
        &mut protocol,
        multisig_prover_admin.clone(),
        gateway.contract_addr.clone(),
        voting_verifier.contract_addr.clone(),
        chain_name.to_string(),
    );

    let response = protocol.coordinator.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &CoordinatorExecuteMsg::RegisterProverContract {
            chain_name: chain_name.clone(),
            new_prover_addr: MockApi::default().addr_make("random_address").to_string(),
        },
    );
    assert!(response.is_ok());

    let response = multisig_prover.execute(
        &mut protocol.app,
        multisig_prover_admin,
        &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
    );

    assert!(response.is_err());
    assert!(response.unwrap_err().to_string().contains(
        &permission_control::Error::WhitelistNotFound {
            sender: multisig_prover.contract_addr.clone()
        }
        .to_string()
    ));
}
