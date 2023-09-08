use connection_router::msg::Message;
use connection_router::types::ID_SEPARATOR;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use gateway::contract::*;
use gateway::error::ContractError;
use gateway::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

use crate::mock::is_verified;
use crate::mock::{
    get_router_messages, make_mock_router, make_mock_verifier, mark_messages_as_verified,
};
pub mod mock;
#[test]
fn verify_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: Addr::unchecked("router").to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let src_chain = "mock-chain-2";
    let msg = Message {
        id: format!("{}{}foobar", src_chain, ID_SEPARATOR,).into(),
        destination_address: "idc".into(),
        destination_chain: "mock-chain".into(),
        source_chain: src_chain.into(),
        source_address: "idc".into(),
        payload_hash: vec![0, 0, 0, 0].into(),
    };

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![]),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.id.clone(), false)]);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone().into()]),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.id.clone(), false)]);

    mark_messages_as_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone().into()]),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.id.clone(), true)]);

    // should still return true if queried again
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone().into()]),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.id, true)]);
}

fn generate_messages(count: usize) -> Vec<connection_router::state::Message> {
    let mut msgs = vec![];
    for x in 0..count {
        let src_chain = "mock-chain";
        let id = format!("{}{}{}", src_chain, ID_SEPARATOR, x);
        msgs.push(connection_router::state::Message::new(
            id.parse().unwrap(),
            "idc".into(),
            "mock-chain-2".parse().unwrap(),
            src_chain.parse().unwrap(),
            "idc".into(),
            vec![x as u8, 0, 0, 0].into(),
        ));
    }
    msgs
}

fn convert_messages(
    msgs: &Vec<connection_router::state::Message>,
) -> Vec<connection_router::msg::Message> {
    msgs.into_iter().map(|m| m.clone().into()).collect()
}

#[test]
fn verify_multiple_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: Addr::unchecked("router").to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs.clone())),
        &[],
    );
    println!("{:?}", res);
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );
}

#[test]
fn verify_multiple_messages_mixed_status() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: Addr::unchecked("router").to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let msgs_verified = &msgs[0..5];
    let msgs_unverified = &msgs[5..10];

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs_verified.to_vec()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified
            .iter()
            .find(|m| m.id.to_string() == id)
            .is_some()
        {
            true
        } else {
            false
        };
        assert_eq!(expected_status, status);
    }

    // same call should return same response
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified
            .iter()
            .find(|m| m.id.to_string() == id)
            .is_some()
        {
            true
        } else {
            false
        };
        assert_eq!(expected_status, status);
    }

    // mark the rest as verified
    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs_unverified.to_vec()),
    );
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );
}

#[test]
fn execute_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(1);
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_multiple_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_multiple_messages_mixed_status() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let msgs_verified = &msgs[0..5];
    let msgs_unverified = &msgs[5..10];

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs_verified.to_vec()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());
    let mut ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified
            .iter()
            .find(|m| m.id.to_string() == id)
            .is_some()
        {
            true
        } else {
            false
        };
        assert_eq!(expected_status, status);
    }
    let ret = get_router_messages(
        &mut app,
        router_address.clone(),
        convert_messages(&msgs_verified.to_vec()),
    );
    assert_eq!(ret, msgs_verified);
    let ret = get_router_messages(
        &mut app,
        router_address,
        convert_messages(&msgs_unverified.to_vec()),
    );
    assert_eq!(ret, vec![]);
}

#[test]
fn execute_not_verified_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(1);
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_pre_verified_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(1);

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_twice() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(1);

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs.clone())),
        &[],
    );
    assert!(res.is_ok());
    let ret: Vec<(String, bool)> = is_verified(
        &mut app,
        verifier_address.clone(),
        convert_messages(&msgs.clone()),
    );
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );
}

#[test]
fn receive_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(1);

    let res = app.execute_contract(
        router_address,
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<connection_router::msg::Message> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id.to_string()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.into_iter().map(|m| m.into()).collect::<Vec<Message>>()
    );
}

#[test]
fn receive_many_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);

    let res = app.execute_contract(
        router_address,
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(convert_messages(&msgs)),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<connection_router::msg::Message> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id.to_string()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.into_iter().map(|m| m.into()).collect::<Vec<Message>>()
    );
}

#[test]
fn duplicate_message_id() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));

    let gateway_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                verifier_address: verifier_address.to_string(),
                router_address: router_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    // make two different messages with the same ID
    let mut msgs = convert_messages(&generate_messages(2));
    msgs[1].id = msgs[0].id.clone();
    assert_ne!(msgs[0], msgs[1]);

    let err = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages(msgs.clone()),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DuplicateMessageID, err.downcast().unwrap());

    let err = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::RouteMessages(msgs.clone()),
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::DuplicateMessageID, err.downcast().unwrap());

    //verify one of them
    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs[0..1].to_vec());
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs[0..1].to_vec()),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), msgs[0..1].to_vec());
    assert_eq!(
        ret,
        msgs[0..1]
            .iter()
            .map(|m| (m.id.to_string(), true))
            .collect::<Vec<(String, bool)>>()
    );

    // other should not be verified
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs[1..2].to_vec()),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<(String, bool)> =
        is_verified(&mut app, verifier_address.clone(), msgs[1..2].to_vec());
    assert_eq!(
        ret,
        msgs[1..2]
            .iter()
            .map(|m| (m.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );
}
