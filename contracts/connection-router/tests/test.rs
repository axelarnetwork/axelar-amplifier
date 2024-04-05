pub mod mock;
mod test_utils;

use std::vec;

use connection_router_api::error::Error;
use connection_router_api::msg::ExecuteMsg;
use connection_router_api::{ChainName, CrossChainId, GatewayDirection, Message};
use cosmwasm_std::Addr;
use cw_multi_test::App;
use integration_tests::contract::Contract;

use crate::test_utils::ConnectionRouterContract;

struct TestConfig {
    app: App,
    admin_address: Addr,
    governance_address: Addr,
    connection_router: ConnectionRouterContract,
}

struct Chain {
    chain_name: ChainName,
    gateway: Addr,
}

fn setup() -> TestConfig {
    let mut app = App::default();

    let admin_address = Addr::unchecked("admin");
    let governance_address = Addr::unchecked("governance");
    let nexus_gateway = Addr::unchecked("nexus_gateway");

    let connection_router = ConnectionRouterContract::instantiate_contract(
        &mut app,
        admin_address.clone(),
        governance_address.clone(),
        nexus_gateway.clone(),
    );

    TestConfig {
        app,
        admin_address,
        governance_address,
        connection_router,
    }
}

fn make_chain(name: &str, config: &mut TestConfig) -> Chain {
    let gateway = mock::make_mock_gateway(&mut config.app);
    Chain {
        chain_name: name.parse().unwrap(),
        gateway,
    }
}

fn register_chain(config: &mut TestConfig, chain: &Chain) {
    let _ = config
        .connection_router
        .execute(
            &mut config.app,
            config.governance_address.clone(),
            &ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
            },
        )
        .unwrap();
}

#[allow(clippy::arithmetic_side_effects)]
fn generate_messages(
    src_chain: &Chain,
    dest_chain: &Chain,
    nonce: &mut usize,
    count: usize,
) -> Vec<Message> {
    let mut msgs = vec![];
    for x in 0..count {
        *nonce += 1;
        let id = format!("tx_id:{}", nonce);
        msgs.push(Message {
            cc_id: CrossChainId {
                id: id.parse().unwrap(),
                chain: src_chain.chain_name.clone(),
            },
            destination_address: "idc".parse().unwrap(),
            destination_chain: dest_chain.chain_name.clone(),
            source_address: "idc".parse().unwrap(),
            payload_hash: [x as u8; 32],
        })
    }
    msgs
}

#[test]
fn freeze_chain() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let nonce = &mut 0;

    // route a message first
    let routed_msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let _ = config
        .connection_router
        .execute(
            &mut config.app,
            eth.gateway.clone(),
            &ExecuteMsg::RouteMessages(vec![routed_msg.clone()]),
        )
        .unwrap();

    let res = config.connection_router.execute(
        &mut config.app,
        config.admin_address.clone(),
        &ExecuteMsg::FreezeChain {
            chain: polygon.chain_name.clone(),
            direction: GatewayDirection::Bidirectional,
        },
    );
    assert!(res.is_ok());

    let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let err = config
        .connection_router
        .execute(
            &mut config.app,
            eth.gateway.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        )
        .unwrap_err();
    // can't route to frozen chain
    test_utils::are_contract_err_strings_equal(
        err,
        Error::ChainFrozen {
            chain: polygon.chain_name.clone(),
        },
    );

    // can't route from frozen chain
    let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
    let err = config
        .connection_router
        .execute(
            &mut config.app,
            polygon.gateway.clone(),
            &ExecuteMsg::RouteMessages(vec![message.clone()]),
        )
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(
        err,
        Error::ChainFrozen {
            chain: polygon.chain_name.clone(),
        },
    );

    // unfreeze and test that everything works correctly
    let _ = config
        .connection_router
        .execute(
            &mut config.app,
            config.admin_address.clone(),
            &ExecuteMsg::UnfreezeChain {
                chain: polygon.chain_name.clone(),
                direction: GatewayDirection::Bidirectional,
            },
        )
        .unwrap();

    // routed message should have been preserved
    let outgoing_messages = mock::get_gateway_messages(
        &mut config.app,
        polygon.gateway.clone(),
        &[routed_msg.clone()],
    );
    assert_eq!(1, outgoing_messages.len());
    assert_eq!(routed_msg.clone(), outgoing_messages[0]);

    // can route to the chain now
    let message = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let res = config.connection_router.execute(
        &mut config.app,
        eth.gateway.clone(),
        &ExecuteMsg::RouteMessages(vec![message.clone()]),
    );
    assert!(res.is_ok());

    // can route from the chain
    let message = &generate_messages(&polygon, &eth, nonce, 1)[0];
    let res = config.connection_router.execute(
        &mut config.app,
        polygon.gateway.clone(),
        &ExecuteMsg::RouteMessages(vec![message.clone()]),
    );
    assert!(res.is_ok());
}

#[test]
fn bad_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let res = config.connection_router.execute(
        &mut config.app,
        config.governance_address.clone(),
        &ExecuteMsg::UpgradeGateway {
            chain: polygon.chain_name.clone(),
            contract_address: Addr::unchecked("some random address")
                .to_string()
                .try_into()
                .unwrap(), // gateway address does not implement required interface
        },
    );

    assert!(res.is_ok());

    let nonce: &mut usize = &mut 0;
    let message = &generate_messages(&eth, &polygon, nonce, 1)[0];

    let res = config.connection_router.execute(
        &mut config.app,
        eth.gateway.clone(),
        &ExecuteMsg::RouteMessages(vec![message.clone()]),
    );
    assert!(res.is_err());
}
