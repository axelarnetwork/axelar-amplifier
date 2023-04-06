use connection_router;
use std::{collections::HashMap, vec};

use connection_router::state::Message;
use cosmwasm_std::{from_binary, Addr};
use cw_multi_test::{App, ContractWrapper, Executor};

use connection_router::contract::*;
use connection_router::error::ContractError;
use connection_router::msg::{ExecuteMsg, InstantiateMsg};
use cosmwasm_std::HexBinary;

#[test]
fn route() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    let domain_eth = "Ethereum";
    let incoming_eth = Addr::unchecked("incoming_eth");
    let outgoing_eth = Addr::unchecked("outgoing_eth");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.to_string(),
                contract_address: incoming_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_eth.to_string(),
                contract_address: outgoing_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let domain_poly = "Polygon";
    let incoming_poly = Addr::unchecked("incoming_poly");
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_poly.to_string(),
                contract_address: incoming_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();
    let mut nonce = 0;
    let mut gen_msgs = |num: u8, source: String, dest: String| {
        let mut msgs = vec![];
        for x in 0..num {
            nonce = nonce + 1;
            let mut id = "id".to_string();
            id.push_str(&nonce.to_string());
            msgs.push(Message {
                id: id,
                destination_address: String::from("idc"),
                destination_domain: dest.clone(),
                source_domain: source.clone(),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![x, x, x, x]),
                redelivered: false,
            })
        }
        msgs
    };

    let msgs = gen_msgs(255, domain_eth.to_string(), domain_poly.to_string());

    for msg in &msgs {
        let _ = app
            .execute_contract(
                incoming_eth.clone(),
                contract_address.clone(),
                &ExecuteMsg::RouteMessage {
                    id: msg.id.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    source_address: msg.source_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                },
                &[],
            )
            .unwrap();
    }

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 1 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(msgs[0..1], msgs_ret);

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(32, msgs_ret.len());
    assert_eq!(msgs[1..33], msgs_ret);

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 256 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(222, msgs_ret.len());
    assert_eq!(msgs[33..], msgs_ret);

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 256 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(0, msgs_ret.len());
    assert_eq!(Vec::<Message>::new(), msgs_ret);

    // try to route a message with the same id
    let msg = &msgs[0];
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
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

    // Should be able to route same id from a different source though
    let _ = app
        .execute_contract(
            incoming_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    let _ = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 1 },
            &[],
        )
        .unwrap();

    {
        // route to non-existing domain
        let msgs = gen_msgs(1, domain_eth.to_string(), "funny-domain".to_string());
        let msg = &msgs[0];
        let res = app
            .execute_contract(
                incoming_eth.clone(),
                contract_address.clone(),
                &ExecuteMsg::RouteMessage {
                    id: msg.id.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    source_address: msg.source_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                },
                &[],
            )
            .unwrap_err();
        assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());
    }

    // make sure messages are routed to the correct domain
    let eth_messages = gen_msgs(50, domain_poly.to_string(), domain_eth.to_string());
    let poly_messages = gen_msgs(50, domain_eth.to_string(), domain_poly.to_string());

    for msg in &eth_messages {
        let _ = app
            .execute_contract(
                incoming_poly.clone(),
                contract_address.clone(),
                &ExecuteMsg::RouteMessage {
                    id: msg.id.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    source_address: msg.source_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                },
                &[],
            )
            .unwrap();
    }

    for msg in &poly_messages {
        let _ = app
            .execute_contract(
                incoming_eth.clone(),
                contract_address.clone(),
                &ExecuteMsg::RouteMessage {
                    id: msg.id.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    source_address: msg.source_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                },
                &[],
            )
            .unwrap();
    }

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 256 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(poly_messages.len(), msgs_ret.len());
    assert_eq!(poly_messages, msgs_ret);

    let res = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 256 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(eth_messages.len(), msgs_ret.len());
    assert_eq!(eth_messages, msgs_ret);
}

#[test]
fn multi_chain_route() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    let chain_names = vec!["ethereum", "polygon", "osmosis", "avalanche", "moonbeam"];
    struct Chain {
        domain: String,
        incoming: Addr,
        outgoing: Addr,
    }
    let mut chains = vec![];
    for n in &chain_names {
        let mut incoming = String::from("incoming");
        incoming.push_str(n.clone());
        let mut outgoing = String::from("outgoing");
        outgoing.push_str(n.clone());
        chains.push(Chain {
            domain: n.to_string(),
            incoming: Addr::unchecked(incoming),
            outgoing: Addr::unchecked(outgoing),
        })
    }
    for c in &chains {
        let _ = app
            .execute_contract(
                admin_addr.clone(),
                contract_address.clone(),
                &ExecuteMsg::RegisterDomain {
                    domain: c.domain.clone(),
                },
                &[],
            )
            .unwrap();

        let _ = app
            .execute_contract(
                admin_addr.clone(),
                contract_address.clone(),
                &ExecuteMsg::RegisterIncomingGateway {
                    domain: c.domain.clone(),
                    contract_address: c.incoming.to_string(),
                },
                &[],
            )
            .unwrap();

        let _ = app
            .execute_contract(
                admin_addr.clone(),
                contract_address.clone(),
                &ExecuteMsg::RegisterOutgoingGateway {
                    domain: c.domain.clone(),
                    contract_address: c.outgoing.to_string(),
                },
                &[],
            )
            .unwrap();
    }

    let mut nonce = 0;
    let mut gen_msgs = |num: u8, source: String, dest: String| {
        let mut msgs = vec![];
        for x in 0..num {
            nonce = nonce + 1;
            let mut id = "id".to_string();
            id.push_str(&nonce.to_string());
            msgs.push(Message {
                id: id,
                destination_address: String::from("idc"),
                destination_domain: dest.clone(),
                source_domain: source.clone(),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![x, x, x, x]),
                redelivered: false,
            })
        }
        msgs
    };

    let mut all_msgs = HashMap::new();
    for d in &chains {
        let mut msgs = vec![];
        for s in &chains {
            let mut sending = gen_msgs(50, s.domain.clone(), d.domain.clone());
            for msg in &sending {
                let _ = app
                    .execute_contract(
                        s.incoming.clone(),
                        contract_address.clone(),
                        &ExecuteMsg::RouteMessage {
                            id: msg.id.clone(),
                            destination_domain: msg.destination_domain.clone(),
                            destination_address: msg.destination_address.clone(),
                            source_address: msg.source_address.clone(),
                            payload_hash: msg.payload_hash.clone(),
                        },
                        &[],
                    )
                    .unwrap();
            }
            msgs.append(&mut sending);
        }
        all_msgs.insert(d.domain.clone(), msgs);
    }

    for d in &chains {
        let expected = all_msgs.get(&d.domain).unwrap();

        let res = app
            .execute_contract(
                d.outgoing.clone(),
                contract_address.clone(),
                &ExecuteMsg::ConsumeMessages {
                    count: expected.len() as u32,
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
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let domain = "Ethereum".to_string();
    let incoming = Addr::unchecked("incoming_gateway");
    let outgoing = Addr::unchecked("outgoing_gateway");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain.clone(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain.clone(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain.clone(),
                contract_address: incoming.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain.clone(),
                contract_address: outgoing.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let res = app
        .execute_contract(
            Addr::unchecked("random"),
            contract_address.clone(),
            &ExecuteMsg::DeregisterDomain {
                domain: domain.clone(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain.clone(),
                contract_address: incoming.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain.clone(),
                contract_address: outgoing.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::DeregisterDomain {
                domain: domain.clone(),
            },
            &[],
        )
        .unwrap();
}

#[test]
fn upgrade() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let domain_eth = "Ethereum";
    let incoming_eth = Addr::unchecked("incoming_eth");

    let domain_poly = "Polygon";
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.to_string(),
                contract_address: incoming_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: "Polygon".to_string(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap();

    let outgoing_poly_2 = Addr::unchecked("outgoing_poly_2");
    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly_2.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id2".to_string(),
                destination_domain: "Polygon".to_string(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap();

    let incoming_eth_2 = Addr::unchecked("incoming_eth_2");
    let _ = app.execute_contract(
        admin_addr.clone(),
        contract_address.clone(),
        &ExecuteMsg::RegisterIncomingGateway {
            domain: domain_eth.to_string(),
            contract_address: incoming_eth_2.to_string(),
        },
        &[],
    );
    let _ = app
        .execute_contract(
            incoming_eth_2.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id3".to_string(),
                destination_domain: "Polygon".to_string(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id4".to_string(),
                destination_domain: "Polygon".to_string(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let res = app
        .execute_contract(
            outgoing_poly_2.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap();

    let msgs: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0].id, "id1");
    assert_eq!(msgs[1].id, "id2");
    assert_eq!(msgs[2].id, "id3");
}

#[test]
fn registration() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    let domain_eth = String::from("Ethereum");
    let incoming_eth = Addr::unchecked("incoming_eth");
    let outgoing_eth = Addr::unchecked("outgoing_eth");

    let domain_poly = String::from("Polygon");
    let incoming_poly = Addr::unchecked("incoming_poly");
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: domain_poly.clone(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: domain_poly.clone(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );
    let res = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.to_string(),
                contract_address: incoming_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: domain_poly.clone(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    // should be able to send messages now
    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: domain_poly.clone(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap();

    // incoming gateways can't consume
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    // only the registered incoming gateway can send messages
    let res = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: "id1".to_string(),
                destination_domain: domain_poly.clone(),
                destination_address: String::from("idc"),
                source_address: String::from("idc"),
                payload_hash: HexBinary::from(vec![0, 0, 1, 1]),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    // should be able to consume the messages now
    let _ = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap();

    // other addresses can't consume
    let res = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_poly.to_string(),
                contract_address: incoming_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    // incoming gateways can't consume
    let res = app
        .execute_contract(
            outgoing_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 32 },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::DomainAlreadyExists {},
        res.downcast().unwrap()
    );

    // register same gateway to a different domain
    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.to_string(),
                contract_address: incoming_poly.to_string(),
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::GatewayAlreadyRegistered {},
        res.downcast().unwrap()
    );

    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_eth.to_string(),
                contract_address: outgoing_poly.to_string(),
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
fn redeliver() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    let domain_eth = String::from("Ethereum");
    let incoming_eth = Addr::unchecked("incoming_eth");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.clone(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.clone(),
                contract_address: incoming_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let domain_poly = String::from("Polygon");
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.clone(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.clone(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let msg = Message {
        id: "id1".to_string(),
        destination_address: String::from("idc"),
        destination_domain: domain_poly.clone(),
        source_domain: domain_eth.clone(),
        source_address: String::from("idc"),
        payload_hash: HexBinary::from(vec![1, 0, 1, 0]),
        redelivered: false,
    };

    // can't redeliver a message that was never delivered in the first place
    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RedeliverMessage {
                msg: Message {
                    id: msg.id.clone(),
                    source_domain: msg.source_domain.clone(),
                    source_address: msg.source_address.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                    redelivered: false,
                },
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::MessageNotFound {}, res.downcast().unwrap());

    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
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

    // router admin can't call route
    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
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

    // incoming gateway can't call redeliver
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RedeliverMessage {
                msg: Message {
                    id: msg.id.clone(),
                    source_domain: msg.source_domain.clone(),
                    source_address: msg.source_address.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                    redelivered: false,
                },
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(ContractError::Unauthorized {}, res.downcast().unwrap());

    // message contents must be exactly the same
    let res = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RedeliverMessage {
                msg: Message {
                    id: msg.id.clone(),
                    source_domain: msg.source_domain.clone(),
                    source_address: msg.source_address.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: String::from("my address hahah"),
                    payload_hash: msg.payload_hash.clone(),
                    redelivered: false,
                },
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        ContractError::MessageHashMismatch {},
        res.downcast().unwrap()
    );

    // all good now
    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RedeliverMessage {
                msg: Message {
                    id: msg.id.clone(),
                    source_domain: msg.source_domain.clone(),
                    source_address: msg.source_address.clone(),
                    destination_domain: msg.destination_domain.clone(),
                    destination_address: msg.destination_address.clone(),
                    payload_hash: msg.payload_hash.clone(),
                    redelivered: false,
                },
            },
            &[],
        )
        .unwrap();

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 2 },
            &[],
        )
        .unwrap();

    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(2, msgs_ret.len());
    let redelivered_msg = Message {
        redelivered: true,
        ..msg.clone()
    };
    assert_eq!(vec![msg, redelivered_msg], msgs_ret);
}

#[test]
pub fn deregister_domain() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let admin_addr = Addr::unchecked("admin");
    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("router"),
            &InstantiateMsg {
                admin_address: admin_addr.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    let domain_eth = String::from("Ethereum");
    let incoming_eth = Addr::unchecked("incoming_eth");
    let outgoing_eth = Addr::unchecked("outgoing_eth");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_eth.to_string(),
                contract_address: incoming_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_eth.to_string(),
                contract_address: outgoing_eth.to_string(),
            },
            &[],
        )
        .unwrap();

    let domain_poly = String::from("Polygon");
    let incoming_poly = Addr::unchecked("incoming_poly");
    let outgoing_poly = Addr::unchecked("outgoing_poly");

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterIncomingGateway {
                domain: domain_poly.to_string(),
                contract_address: incoming_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let msg = Message {
        id: "id1".to_string(),
        destination_address: String::from("idc"),
        destination_domain: domain_poly.clone(),
        source_domain: domain_eth.clone(),
        source_address: String::from("idc"),
        payload_hash: HexBinary::from(vec![1, 0, 1, 0]),
        redelivered: false,
    };

    let _ = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: msg.id.clone(),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap();
    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::DeregisterDomain {
                domain: domain_poly.clone(),
            },
            &[],
        )
        .unwrap();
    let res = app
        .execute_contract(
            incoming_eth.clone(),
            contract_address.clone(),
            &ExecuteMsg::RouteMessage {
                id: String::from("some different id"),
                destination_domain: msg.destination_domain.clone(),
                destination_address: msg.destination_address.clone(),
                source_address: msg.source_address.clone(),
                payload_hash: msg.payload_hash.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DomainNotFound {}, res.downcast().unwrap());

    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 1 },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::GatewayNotRegistered {},
        res.downcast().unwrap()
    );

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterDomain {
                domain: domain_poly.to_string(),
            },
            &[],
        )
        .unwrap();

    let _ = app
        .execute_contract(
            admin_addr.clone(),
            contract_address.clone(),
            &ExecuteMsg::RegisterOutgoingGateway {
                domain: domain_poly.to_string(),
                contract_address: outgoing_poly.to_string(),
            },
            &[],
        )
        .unwrap();
    let res = app
        .execute_contract(
            outgoing_poly.clone(),
            contract_address.clone(),
            &ExecuteMsg::ConsumeMessages { count: 1 },
            &[],
        )
        .unwrap();
    let msgs_ret: Vec<Message> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(1, msgs_ret.len());
    assert_eq!(vec![msg], msgs_ret);
}
