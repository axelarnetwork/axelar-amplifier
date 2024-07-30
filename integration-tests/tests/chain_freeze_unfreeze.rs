use cosmwasm_std::{Addr, HexBinary};
use integration_tests::contract::Contract;
use router_api::{CrossChainId, Message};

pub mod test_utils;

// Tests that a chain can be frozen and unfrozen
#[test]
fn chain_can_be_freezed_unfreezed() {
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

    test_utils::route_messages(&mut protocol.app, &chain1.gateway, &msgs);

    test_utils::freeze_chain(
        &mut protocol.app,
        &protocol.router,
        chain1.chain_name.clone(),
        router_api::GatewayDirection::Bidirectional,
        &protocol.router_admin_address,
    );

    let response = chain1.gateway.execute(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &gateway_api::msg::ExecuteMsg::RouteMessages(msgs.to_vec()),
    );
    test_utils::assert_contract_err_strings_equal(
        response.unwrap_err(),
        router_api::error::Error::ChainFrozen {
            chain: chain1.chain_name.clone(),
        },
    );

    test_utils::unfreeze_chain(
        &mut protocol.app,
        &protocol.router,
        &chain1.chain_name,
        router_api::GatewayDirection::Bidirectional,
        &protocol.router_admin_address,
    );

    // routed message should have been preserved
    let found_msgs =
        test_utils::messages_from_gateway(&mut protocol.app, &chain2.gateway, &msg_ids);
    assert_eq!(found_msgs, msgs);

    // can route again
    test_utils::route_messages(&mut protocol.app, &chain1.gateway, &msgs);
}
