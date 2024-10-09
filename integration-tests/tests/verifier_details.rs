pub mod test_utils;

#[test]
fn verifier_information_should_be_consistent_in_coordinator() {
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        verifiers,
        ..
    } = test_utils::setup_test_case();

    let chains = vec![ethereum, polygon];
    let first_verifier_info = test_utils::verifier_info_from_coordinator(
        &mut protocol,
        verifiers.first().unwrap().addr.clone(),
    );

    test_utils::assert_verifier_details_are_equal(
        first_verifier_info,
        verifiers.first().unwrap(),
        &chains,
    );

    let second_verifier_info = test_utils::verifier_info_from_coordinator(
        &mut protocol,
        verifiers.get(1).unwrap().addr.clone(),
    );

    test_utils::assert_verifier_details_are_equal(
        second_verifier_info,
        verifiers.get(1).unwrap(),
        &chains,
    );
}
