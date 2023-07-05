use connection_router::{self, msg, state};
use std::{collections::HashMap, vec};

use connection_router::types::{DomainName, ID_SEPARATOR};
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use connection_router::contract::*;
use connection_router::error::ContractError;
use connection_router::msg::{ExecuteMsg, InstantiateMsg};
use cosmwasm_std::HexBinary;
pub mod mock;

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

fn make_chain(name: &str, config: &mut TestConfig) -> Chain {
    let outgoing_gateway = mock::make_mock_gateway(&mut config.app);
    Chain {
        domain_name: name.parse().unwrap(),
        outgoing_gateway: outgoing_gateway,
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
) -> Vec<msg::Message> {
    let mut msgs = vec![];
    for x in 0..count {
        *nonce = *nonce + 1;
        let id = format!("id-{}", nonce);
        msgs.push(msg::Message {
            id: id.parse().unwrap(),
            destination_address: String::from("idc"),
            destination_domain: dest_chain.domain_name.to_string(),
            source_domain: src_chain.domain_name.to_string(),
            source_address: String::from("idc"),
            payload_hash: HexBinary::from(vec![x as u8; 256]),
        })
    }
    msgs
}

fn get_base_id(msg: &state::Message) -> String {
    msg.id()
        .to_string()
        .split_once(ID_SEPARATOR)
        .unwrap()
        .1
        .to_string()
}

// tests that each message is properly delivered
#[test]
fn route() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let nonce: &mut usize = &mut 0;
    let msgs = generate_messages(&eth, &polygon, nonce, 255);

    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(msgs.clone()),
            &[],
        )
        .unwrap();

    let msgs_ret = mock::get_gateway_messages(&mut config.app, polygon.outgoing_gateway, &msgs);

    assert_eq!(msgs.len(), msgs_ret.len());
    assert_eq!(msgs, msgs_ret);
}

#[test]
fn route_non_existing_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());
}

#[test]
fn message_id() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let msg2 = &generate_messages(&polygon, &eth, &mut 0, 1)[0];
    {
        let msg = state::Message::try_from(msg.clone()).unwrap();
        let msg2 = state::Message::try_from(msg2.clone()).unwrap();
        assert_eq!(get_base_id(&msg), get_base_id(&msg2));
        assert_ne!(msg.id(), msg2.id());
    }
    // try to route same message twice
    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap();

    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::MessageAlreadyRouted {
            id: state::Message::try_from(msg.clone()).unwrap().id()
        },
        res.downcast().unwrap()
    );

    // Should be able to route same id from a different source
    let _ = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg::Message {
                source_domain: polygon.domain_name.to_string(),
                ..msg.clone()
            }]),
            &[],
        )
        .unwrap();

    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg::Message {
                id: "bad:".to_string(),
                ..msg.clone()
            }]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidMessageID {}, res.downcast().unwrap());

    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg::Message {
                id: "".to_string(),
                ..msg.clone()
            }]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidMessageID {}, res.downcast().unwrap());
}

#[test]
fn invalid_address() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];

    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg::Message {
                destination_address: "".to_string(),
                ..msg.clone()
            }]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidAddress {}, res.downcast().unwrap());

    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg::Message {
                source_address: "".to_string(),
                ..msg.clone()
            }]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidAddress {}, res.downcast().unwrap());
}

#[test]
fn wrong_source_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];

    let res = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::WrongSourceDomain {}, res.downcast().unwrap());
}

#[test]
fn multi_chain_route() {
    let mut config = setup();
    let chains = vec![
        make_chain("ethereum", &mut config),
        make_chain("polygon", &mut config),
        make_chain("osmosis", &mut config),
        make_chain("avalanche", &mut config),
        make_chain("moonbeam", &mut config),
    ];
    for c in &chains {
        register_chain(&mut config, c);
    }

    let nonce = &mut 0;
    let mut all_msgs_by_dest = HashMap::new();
    let mut all_msgs_by_src = HashMap::new();
    for d in &chains {
        let mut msgs = vec![];
        for s in &chains {
            let mut sending = generate_messages(&s, &d, nonce, 50);

            all_msgs_by_src
                .entry(s.domain_name.to_string())
                .or_insert(vec![])
                .append(&mut sending);

            msgs.append(&mut sending);
        }
        all_msgs_by_dest.insert(d.domain_name.to_string(), msgs);
    }

    for s in &chains {
        let res = config.app.execute_contract(
            s.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(
                all_msgs_by_src
                    .get_mut(&s.domain_name.to_string())
                    .unwrap()
                    .clone(),
            ),
            &[],
        );
        assert!(res.is_ok());
    }

    for d in &chains {
        let expected = all_msgs_by_dest.get(&d.domain_name.to_string()).unwrap();

        let actual =
            mock::get_gateway_messages(&mut config.app, d.outgoing_gateway.clone(), expected);
        assert_eq!(expected.len(), actual.len());
        assert_eq!(expected, &actual);
    }
}

#[test]
fn authorization() {
    let mut config = setup();

    let chain = make_chain("ethereum", &mut config);

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: chain.domain_name.to_string(),
                incoming_gateway_address: chain.incoming_gateway.to_string(),
                outgoing_gateway_address: chain.outgoing_gateway.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RegisterDomain {
            domain: chain.domain_name.to_string(),
            incoming_gateway_address: chain.incoming_gateway.to_string(),
            outgoing_gateway_address: chain.outgoing_gateway.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::FreezeDomain {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::FreezeDomain {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::UnfreezeDomain {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UnfreezeDomain {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );

    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeIncomingGateway {
                domain: chain.domain_name.to_string(),
                contract_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UpgradeIncomingGateway {
            domain: chain.domain_name.to_string(),
            contract_address: Addr::unchecked("new gateway").to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::UpgradeOutgoingGateway {
                domain: chain.domain_name.to_string(),
                contract_address: Addr::unchecked("new gateway").to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UpgradeOutgoingGateway {
            domain: chain.domain_name.to_string(),
            contract_address: Addr::unchecked("new gateway").to_string(),
        },
        &[],
    );

    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::UnfreezeIncomingGateway {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UnfreezeIncomingGateway {
            domain: chain.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = config
        .app
        .execute_contract(
            Addr::unchecked("random"),
            config.contract_address.clone(),
            &ExecuteMsg::UnfreezeOutgoingGateway {
                domain: chain.domain_name.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
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
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let new_gateway = mock::make_mock_gateway(&mut config.app);
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

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap();

    let msgs = mock::get_gateway_messages(&mut config.app, new_gateway, &vec![msg.clone()]);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msg.clone(), msgs[0]);
}

#[test]
fn upgrade_incoming_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

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
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
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
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());
    let msgs =
        mock::get_gateway_messages(&mut config.app, eth.outgoing_gateway, &vec![msg.clone()]);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], msg.clone());
}

#[test]
fn register_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
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
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());

    register_chain(&mut config, &polygon);
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());
}

#[test]
fn domain_already_registered() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
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
                domain: "bad:".to_string(),
                incoming_gateway_address: Addr::unchecked("incoming").to_string(),
                outgoing_gateway_address: Addr::unchecked("outgoing").to_string(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::InvalidDomainName {}, res.downcast().unwrap());

    let res = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: "".to_string(),
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
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);
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
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);
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
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    // can still route to domain
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());
    let msgs = mock::get_gateway_messages(
        &mut config.app,
        polygon.outgoing_gateway,
        &vec![msg.clone()],
    );
    assert_eq!(&msgs[0], msg);
}

#[test]
fn freeze_outgoing_gateway() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    // freeze outgoing
    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::FreezeOutgoingGateway {
            domain: polygon.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    // can still send to the domain, messages will queue up
    let msg = &generate_messages(&eth, &polygon, &mut 0, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::GatewayFrozen {}, res.downcast().unwrap());

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
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());
    let msgs = mock::get_gateway_messages(
        &mut config.app,
        polygon.outgoing_gateway,
        &vec![msg.clone()],
    );
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], msg.clone());
}

#[test]
fn freeze_domain() {
    let mut config = setup();
    let eth = make_chain("ethereum", &mut config);
    let polygon = make_chain("polygon", &mut config);
    register_chain(&mut config, &eth);
    register_chain(&mut config, &polygon);

    let nonce = &mut 0;
    // route a message first
    let routed_msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let _ = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![routed_msg.clone()]),
            &[],
        )
        .unwrap();

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::FreezeDomain {
            domain: polygon.domain_name.to_string(),
        },
        &[],
    );
    assert!(res.is_ok());

    let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let res = config
        .app
        .execute_contract(
            eth.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    // can't route to frozen domain
    assert_eq!(
        ContractError::DomainFrozen {
            domain: polygon.domain_name.clone()
        },
        res.downcast().unwrap()
    );

    // can't route from frozen domain
    let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
    let res = config
        .app
        .execute_contract(
            polygon.incoming_gateway.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::RouteMessages(vec![msg.clone()]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DomainFrozen {
            domain: polygon.domain_name.clone(),
        },
        res.downcast().unwrap()
    );

    // unfreeze and test that everything works correctly
    let _ = config
        .app
        .execute_contract(
            config.admin_address.clone(),
            config.contract_address.clone(),
            &ExecuteMsg::UnfreezeDomain {
                domain: polygon.domain_name.to_string(),
            },
            &[],
        )
        .unwrap();

    // routed message should have been preserved
    let msgs_ret = mock::get_gateway_messages(
        &mut config.app,
        polygon.outgoing_gateway.clone(),
        &vec![routed_msg.clone()],
    );
    assert_eq!(1, msgs_ret.len());
    assert_eq!(routed_msg.clone(), msgs_ret[0]);

    // can route to the domain now
    let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];
    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());

    // can route from the domain
    let msg = &generate_messages(&polygon, &eth, nonce, 1)[0];
    let res = config.app.execute_contract(
        polygon.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
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

    let res = config.app.execute_contract(
        config.admin_address.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::UpgradeOutgoingGateway {
            domain: polygon.domain_name.to_string(),
            contract_address: Addr::unchecked("some random address").to_string(), // gateway address does not implement required interface
        },
        &[],
    );

    assert!(res.is_ok());

    let nonce: &mut usize = &mut 0;
    let msg = &generate_messages(&eth, &polygon, nonce, 1)[0];

    let res = config.app.execute_contract(
        eth.incoming_gateway.clone(),
        config.contract_address.clone(),
        &ExecuteMsg::RouteMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_err());
}
