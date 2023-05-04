use connection_router;
use std::str::FromStr;
use std::{collections::HashMap, vec};

use connection_router::state::{DomainName, Message};
use cosmwasm_std::{from_binary, Addr};
use cw_multi_test::{App, ContractWrapper, Executor};

use connection_router::contract::*;
use connection_router::error::ContractError;
use connection_router::msg::{ExecuteMsg, InstantiateMsg};
use cosmwasm_std::HexBinary;

struct TestConfig {
    app: cw_multi_test::App,
    contract_address: Addr,
    admin_address: Addr,
}

struct Chain {
    domain_name: DomainName,
    outgoing_gateway: Addr,
    incoming_gateway: Addr,
}

fn setup() -> TestConfig {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_address = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    TestConfig {
        app,
        contract_address,
        admin_address,
    }
}

fn make_chain(name: &str) -> Chain {
    Chain {
        domain_name: DomainName::from_str(name).unwrap(),
        outgoing_gateway: Addr::unchecked(format!("{}_outgoing", name)),
        incoming_gateway: Addr::unchecked(format!("{}_incoming", name)),
    }
}

fn register_chain(config: &mut TestConfig, chain: &Chain) {
    let _ = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: chain.domain_name.to_string(),
                incoming_gateway_address: chain.incoming_gateway.to_string(),
                outgoing_gateway_address: chain.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap();
}

fn generate_messages(
    src_chain: &Chain,
    dest_chain: &Chain,
    nonce: &mut usize,
    count: usize,
) -> Vec<Message> {
    let mut msgs = vec![];
    for x in 0..count {
        *nonce = *nonce + 1;
        let id = format!("id-{}", nonce);
        msgs.push(Message {
            id: id,
            destination_address: String::from("idc"),
            destination_domain: dest_chain.domain_name.clone(),
            source_domain: src_chain.domain_name.clone(),
            source_address: String::from("idc"),
            payload_hash: HexBinary::from(vec![x as u8; 256]),
        })
    }
    msgs
}

// tests that each message is properly delivered and consumed only once
#[test]
fn route() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let nonce: &mut usize = &mut 0;
    let msgs = generate_messages(&eth, &polygon, nonce, 255);

    for msg in &msgs {
        let _ = config
            .app
            .execute_contract(
                eth.incoming_gateway.clone(),
                config.contract_address.clone(),
                &ExecuteMsg::RouteMessage {
                    id: msg.id.clone(),
                    destination_domain: msg.destination_domain.to_string(),
                    destination_address: msg.destination_address.to_string(),
                    source_address: msg.source_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                },
                &[],
            )
            .unwrap();
    }

    let mut offset = 0;
    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(msgs[offset..msgs_ret.len()], msgs_ret);
    offset = offset + 1;

    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(32) },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(32, msgs_ret.len());
    assert_eq!(msgs[offset..offset + msgs_ret.len()], msgs_ret);
    offset = offset + msgs_ret.len();

    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(256) },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(msgs.len() - offset, msgs_ret.len());
    assert_eq!(msgs[offset..], msgs_ret);

    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(256) },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(0, msgs_ret.len());
    assert_eq!(Vec::<Message>::new(), msgs_ret);
}

#[test]
fn route_non_existing_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    register_chain(&mut config, &eth);
    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.to_string(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());
}

#[test]
fn message_id() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let msg2 = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
    assert_eq!(msg.id, msg2.id);
    assert_ne!(msg.uuid(), msg2.uuid());

    // try to route same message twice
    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.to_string(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.to_string(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::MessageAlreadyRouted { id: msg.uuid() },
        res.downcast().unwrap()
    );

    // Should be able to route same id from a different source
    let _ = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.to_string(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
}

#[test]
fn multi_chain_route() {
    let mut config = setup();
    let chains = vec![
        make_chain("ethereum"),
        make_chain("polygon"),
        make_chain("osmosis"),
        make_chain("avalanche"),
        make_chain("moonbeam"),
    ];
    for c in &chains {
        register_chain(&mut config, c);
    }

    let nonce = &mut 0;
    let mut all_msgs = HashMap::new();
    for d in &chains {
        let mut msgs = vec![];
        for s in &chains {
            let mut sending = generate_messages(&s, &d, nonce, 50);
            for msg in &sending {
                let res = config.app.execute_contract(
                    s.incoming_gateway.clone(),
                    config.contract_address.clone(),
                    &ExecuteMsg::RouteMessage {
                        id: msg.id.clone(),
                        destination_domain: msg.destination_domain.to_string(),
                        destination_address: msg.destination_address.clone(),
                        source_address: msg.source_address.clone(),
                        payload_hash: msg.payload_hash.clone(),
                    },
                    &[],
                );
                assert!(res.is_ok());
            }
            msgs.append(&mut sending);
        }
        all_msgs.insert(d.domain_name.to_string(), msgs);
    }

    for d in &chains {
        let expected = all_msgs.get(&d.domain_name.to_string()).unwrap();

        let res = config
            .app
            .execute_contract(
                d.outgoing_gateway.clone(),
                config.contract_address.clone(),
                &ExecuteMsg::ConsumeMessages {
                    count: Some(expected.len() as u32),
                },
                &[],
            )
            .unwrap();
        let actual: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(expected.len(), actual.len());
        assert_eq!(expected, &actual);
    }
}

#[test]
fn authorization() {
    let TestConfig {
        mut app,
        contract_address,
        admin_address,
    } = setup();

    let chain = make_chain("ethereum");

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: chain.domain_name.to_string(),
                incoming_gateway_address: chain.incoming_gateway.to_string(),
                outgoing_gateway_address: chain.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::RegisterDomain {
            domain: chain.domain_name.to_string(),
            incoming_gateway_address: chain.incoming_gateway.to_string(),
            outgoing_gateway_address: chain.outgoing_gateway.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::FreezeDomain {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::FreezeDomain {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeDomain {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::UnfreezeDomain {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );

    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::UpgradeIncomingGateway {
                domain: chain.domain_name.to_string(),
                contract_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::UpgradeIncomingGateway {
            domain: chain.domain_name.to_string(),
            contract_address: Addr::unchecked("new gateway").to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::UpgradeOutgoingGateway {
                domain: chain.domain_name.to_string(),
                contract_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::UpgradeOutgoingGateway {
            domain: chain.domain_name.to_string(),
            contract_address: Addr::unchecked("new gateway").to_string(),
        },
        &[],
    );

    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeIncomingGateway {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::UnfreezeIncomingGateway {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeOutgoingGateway {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app.execute_contract(
        admin_address.clone(),
        contract_address.clone(),
        &ExecuteMsg::UnfreezeOutgoingGateway {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());
}

#[test]
fn upgrade_outgoing_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    // queue a message
    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    let new_gateway = Addr::unchecked("polygon_outgoing_gateway_2");
    let _ = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeOutgoingGateway {
                domain: polygon.domain_name.to_string(),
                contract_address: new_gateway.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(32) },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );
    let res = config
        .app
        .execute_contract(
            new_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(32) },
            &[],
        )
        .unwrap();

    let msgs: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], *msg);
}

#[test]
fn upgrade_incoming_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);
    let new_gateway = Addr::unchecked("polygon_incoming_gateway_2");

    let _ = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeIncomingGateway {
                domain: polygon.domain_name.to_string(),
                contract_address: new_gateway.to_string(),
            },
            &[],
        )
        .unwrap();

    let msg = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let res = config.app.execute_contract(
        new_gateway,
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessage {
            id: msg.id.clone(),
            destination_domain: msg.destination_domain.to_string(),
            destination_address: msg.destination_address.clone(),
            source_address: msg.source_address.clone(),
            payload_hash: msg.payload_hash.clone(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = config
        .app
        .execute_contract(
            eth.outgoing_gateway,
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(32) },
            &[],
        )
        .unwrap();

    let msgs: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], *msg);
}

#[test]
fn register_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );
    register_chain(&mut config, &eth);
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());
    register_chain(&mut config, &polygon);
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessage {
            id: msg.id.clone(),
            destination_domain: msg.destination_domain.to_string(),
            destination_address: msg.destination_address.clone(),
            source_address: msg.source_address.clone(),
            payload_hash: msg.payload_hash.clone(),
        },
        &[],
    );
    assert!(res.is_ok());
}

#[test]
fn domain_already_registered() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    register_chain(&mut config, &eth);

    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: eth.domain_name.to_string(),
                incoming_gateway_address: Addr::unchecked("new gateway").to_string(),
                outgoing_gateway_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainAlreadyExists {},
        res.downcast().unwrap()
    );

    // case insensitive
    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: "ETHEREUM".to_string(),
                incoming_gateway_address: Addr::unchecked("new gateway").to_string(),
                outgoing_gateway_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainAlreadyExists {},
        res.downcast().unwrap()
    );
}

#[test]
fn invalid_domain_name() {
    let mut config = setup();
    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: "bad-".to_string(),
                incoming_gateway_address: Addr::unchecked("incoming").to_string(),
                outgoing_gateway_address: Addr::unchecked("outgoing").to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidDomainName {}, res.downcast().unwrap());
}

#[test]
fn gateway_already_registered() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");
    register_chain(&mut config, &eth);
    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: polygon.domain_name.to_string(),
                incoming_gateway_address: eth.incoming_gateway.to_string(),
                outgoing_gateway_address: polygon.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayAlreadyRegistered {},
        res.downcast().unwrap()
    );
    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: polygon.domain_name.to_string(),
                incoming_gateway_address: polygon.incoming_gateway.to_string(),
                outgoing_gateway_address: eth.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayAlreadyRegistered {},
        res.downcast().unwrap()
    );

    register_chain(&mut config, &polygon);
    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeIncomingGateway {
                domain: eth.domain_name.to_string(),
                contract_address: polygon.incoming_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayAlreadyRegistered {},
        res.downcast().unwrap()
    );

    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeOutgoingGateway {
                domain: eth.domain_name.to_string(),
                contract_address: polygon.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayAlreadyRegistered {},
        res.downcast().unwrap()
    );
}

#[test]
fn freeze_incoming_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let _ = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::FreezeIncomingGateway {
                domain: polygon.domain_name.to_string(),
            },
            &[],
        )
        .unwrap();

    let msg = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
    // can't route from frozen incoming gateway
    let res = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    // can still route to domain
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessage {
            id: msg.id.clone(),
            destination_domain: msg.destination_domain.to_string(),
            destination_address: msg.destination_address.clone(),
            source_address: msg.source_address.clone(),
            payload_hash: msg.payload_hash.clone(),
        },
        &[],
    );
    assert!(res.is_ok());

    // can still consume
    let res = config.app.execute_contract(
        polygon.outgoing_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::ConsumeMessages { count: None },
        &[],
    );
    assert!(res.is_ok());
}

#[test]
fn freeze_outgoing_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    // now freeze outgoing
    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::FreezeOutgoingGateway {
            domain: polygon.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            polygon.outgoing_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: None },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    // can still send to the domain, messages will queue up
    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessage {
            id: msg.id.clone(),
            destination_domain: msg.destination_domain.to_string(),
            destination_address: msg.destination_address.clone(),
            source_address: msg.source_address.clone(),
            payload_hash: msg.payload_hash.clone(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UnfreezeOutgoingGateway {
            domain: polygon.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config.app.execute_contract(
        polygon.outgoing_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::ConsumeMessages { count: None },
        &[],
    );
    assert!(res.is_ok());
    let msgs: Vec<Message> = from_binary(&res.unwrap().data.unwrap()).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], *msg);
}
/*
#[test]
fn freeze_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum");
    let polygon = make_chain("polygon");
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let _ = config.app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::FreezeDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();
    // can't route to frozen domain
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone()
        },
        res.downcast().unwrap()
    );

    // can't route from frozen domain
    let res = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone(),
        },
        res.downcast().unwrap()
    );

    // frozen domain can't consume
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone()
        },
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap();
    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(vec![msg.clone()], msgs_ret);

    // routing should succeed now
    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
}

#[test]
pub fn freeze() {
    let TestConfig {
        mut app,
        contract_address,
        admin_address,
    } = setup();
    let domain_eth = DomainName::from_str("ethereum").unwrap();
    let incoming_eth = Addr::unchecked("incoming_eth");
    let outgoing_eth = Addr::unchecked("outgoing_eth");

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.to_string(),
                incoming_gateway_address: incoming_eth.to_string(),
                outgoing_gateway_address: outgoing_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let domain_poly = DomainName::from_str("polygon").unwrap();
    let incoming_poly = Addr::unchecked("incoming_poly");
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
                incoming_gateway_address: incoming_poly.to_string(),
                outgoing_gateway_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let mut id = 1;
    let mut get_id = || {
        id = id + 1;
        id
    };

    let msg = Message {
        id: get_id().to_string(),
        destination_address: String::from("idc"),
        destination_domain: domain_poly.clone(),
        source_domain: domain_eth.clone(),
        source_address: String::from("idc"),
        payload_hash: HexBinary::from(vec![1, 0, 1, 0]),
    };

    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::FreezeDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();
    // can't route to frozen domain
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone()
        },
        res.downcast().unwrap()
    );

    // can't route from frozen domain
    let res = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone(),
        },
        res.downcast().unwrap()
    );

    // frozen domain can't consume
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: domain_poly.clone()
        },
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap();
    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(vec![msg.clone()], msgs_ret);

    // routing should succeed now
    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: msg.destination_domain.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    // clear out the queues
    let _ = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: Some(1) },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::FreezeIncomingGateway {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();
    // can't route from frozen incoming gateway
    let res = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    // can still route to domain
    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_poly.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    // can still consume
    let _ = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: None },
            &[],
        )
        .unwrap();

    // now freeze outgoing
    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::FreezeOutgoingGateway {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: None },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    let queued_id = get_id();
    // can still route to domain, messages will queue up
    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: queued_id.to_string(),
                destination_domain: domain_poly.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    // incoming should still be frozen
    let res = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeIncomingGateway {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    // incoming can route now
    let _ = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: get_id().to_string(),
                destination_domain: domain_eth.to_string(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    // outgoing should still be frozen
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: None },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            admin_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::UnfreezeOutgoingGateway {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    // messages routed while frozen should have queued
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: None },
            &[],
        )
        .unwrap();
    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(queued_id.to_string(), msgs_ret[0].id);
}
*/
