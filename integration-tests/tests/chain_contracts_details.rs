use coordinator::msg::ChainContractsKey;

pub mod test_utils;

#[test]
fn chain_contracts_information_should_be_consistent_in_coordinator() {
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        ..
    } = test_utils::setup_test_case();

    let ethereum_by = test_utils::chain_contracts_info_from_coordinator(
        &mut protocol,
        ChainContractsKey::ChainName(ethereum.chain_name.clone()),
    );

    test_utils::assert_chain_contracts_details_are_equal(ethereum_by, &ethereum);

    let ethereum_by = test_utils::chain_contracts_info_from_coordinator(
        &mut protocol,
        ChainContractsKey::GatewayAddress(ethereum.gateway.contract_addr.clone()),
    );

    test_utils::assert_chain_contracts_details_are_equal(ethereum_by, &ethereum);

    let ethereum_by = test_utils::chain_contracts_info_from_coordinator(
        &mut protocol,
        ChainContractsKey::ProverAddress(ethereum.multisig_prover.contract_addr.clone()),
    );

    test_utils::assert_chain_contracts_details_are_equal(ethereum_by, &ethereum);

    let ethereum_by = test_utils::chain_contracts_info_from_coordinator(
        &mut protocol,
        ChainContractsKey::VerifierAddress(ethereum.voting_verifier.contract_addr.clone()),
    );

    test_utils::assert_chain_contracts_details_are_equal(ethereum_by, &ethereum);
}
