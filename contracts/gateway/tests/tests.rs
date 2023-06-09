use connection_router::msg::Message;
use cosmwasm_std::from_binary;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use gateway::contract::*;
use gateway::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use gateway::{error::ContractError, state::MessageStatus};

use crate::mock::{
    get_router_messages, make_mock_router, make_mock_verifier, mark_messages_as_verified,
};
pub mod mock;
#[test]
fn verify_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages { messages: vec![] },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![]);

    let msg = Message {
        id: "foobar".into(),
        destination_address: "idc".into(),
        destination_domain: "cj-chain".into(),
        source_domain: "cj-chain-2".into(),
        source_address: "idc".into(),
        payload_hash: vec![0, 0, 0, 0].into(),
    };
    let msg_s = connection_router::state::Message::try_from(msg.clone()).unwrap();
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: vec![msg.clone().into()],
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![(msg_s.id(), MessageStatus::Received)]);

    mark_messages_as_verified(&mut app, verifier_address, vec![msg.clone()]);

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: vec![msg.clone().into()],
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![(msg_s.id(), MessageStatus::Verified)]);

    // should still return true if queried again
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: vec![msg.clone().into()],
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![(msg_s.id(), MessageStatus::Verified)]);
}

fn generate_messages(count: usize) -> Vec<connection_router::state::Message> {
    let mut msgs = vec![];
    for x in 0..count {
        msgs.push(connection_router::state::Message::new(
            x.to_string().parse().unwrap(),
            "idc".into(),
            "cj-chain".parse().unwrap(),
            "cj-chain-2".parse().unwrap(),
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

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Received))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );
}

#[test]
fn verify_multiple_messages_mixed_status() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified.iter().find(|m| m.id() == id).is_some() {
            MessageStatus::Verified
        } else {
            MessageStatus::Received
        };
        assert_eq!(expected_status, status);
    }

    // same call should return same response
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified.iter().find(|m| m.id() == id).is_some() {
            MessageStatus::Verified
        } else {
            MessageStatus::Received
        };
        assert_eq!(expected_status, status);
    }

    // mark the rest as verified
    mark_messages_as_verified(
        &mut app,
        verifier_address,
        convert_messages(&msgs_unverified.to_vec()),
    );
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );
}

#[test]
fn execute_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Received))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Executed))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_multiple_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Received))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Executed))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_multiple_messages_mixed_status() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let mut ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    ret.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ret.len(), msgs.len());
    for (id, status) in ret {
        let expected_status = if msgs_verified.iter().find(|m| m.id() == id).is_some() {
            MessageStatus::Executed
        } else {
            MessageStatus::Received
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

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Received))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Executed))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_pre_verified_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Executed))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);
}

#[test]
fn execute_twice() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), MessageStatus::Executed))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    let ret = get_router_messages(&mut app, router_address, convert_messages(&msgs));
    assert_eq!(ret, msgs);

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: convert_messages(&msgs.clone()),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::MessageAlreadyExecuted {
            message_id: msgs[0].id()
        },
        res.downcast().unwrap()
    );
}

#[test]
fn send_one_message() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let _ = app
        .execute_contract(
            router_address,
            gateway_address.clone(),
            &ExecuteMsg::SendMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.into(), MessageStatus::Sent))
            .collect::<Vec<(Message, MessageStatus)>>()
    );
}

#[test]
fn send_many_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let _ = app
        .execute_contract(
            router_address,
            gateway_address.clone(),
            &ExecuteMsg::SendMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.into_iter()
            .map(|m| (m.into(), MessageStatus::Sent))
            .collect::<Vec<(Message, MessageStatus)>>()
    );
}

#[test]
fn send_message_not_router() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let res = app
        .execute_contract(
            Addr::unchecked("anyone"),
            gateway_address.clone(),
            &ExecuteMsg::SendMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(ContractError::SenderNotRouter {}, res.downcast().unwrap());
}

#[test]
fn get_received_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let msgs = generate_messages(5);
    app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages {
            messages: convert_messages(&msgs.clone()),
        },
        &[],
    )
    .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address.clone(),
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.clone().into(), MessageStatus::Received))
            .collect::<Vec<(Message, MessageStatus)>>()
    );
}

#[test]
fn get_executed_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let msgs = generate_messages(5);
    app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::ExecuteMessages {
            messages: convert_messages(&msgs.clone()),
        },
        &[],
    )
    .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address.clone(),
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.clone().into(), MessageStatus::Received))
            .collect::<Vec<(Message, MessageStatus)>>()
    );

    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));

    app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::ExecuteMessages {
            messages: convert_messages(&msgs.clone()),
        },
        &[],
    )
    .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address.clone(),
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.clone().into(), MessageStatus::Executed))
            .collect::<Vec<(Message, MessageStatus)>>()
    );
}

#[test]
fn get_verified_messages() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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

    let msgs = generate_messages(5);
    mark_messages_as_verified(&mut app, verifier_address, convert_messages(&msgs.clone()));
    app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages {
            messages: convert_messages(&msgs.clone()),
        },
        &[],
    )
    .unwrap();

    let ret: Vec<(connection_router::msg::Message, MessageStatus)> = app
        .wrap()
        .query_wasm_smart(
            gateway_address.clone(),
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|m| m.id()).collect(),
            },
        )
        .unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.clone().into(), MessageStatus::Verified))
            .collect::<Vec<(Message, MessageStatus)>>()
    );
}

#[test]
fn duplicate_message_id() {
    let mut app = App::default();
    let verifier_address = make_mock_verifier(&mut app);
    let router_address = make_mock_router(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
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
            &ExecuteMsg::VerifyMessages {
                messages: msgs.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DuplicateMessageID {},
        err.downcast().unwrap()
    );

    let err = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::ExecuteMessages {
                messages: msgs.clone(),
            },
            &[],
        )
        .unwrap_err();
    assert_eq!(
        ContractError::DuplicateMessageID {},
        err.downcast().unwrap()
    );

    //verify one of them
    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs[0..1].to_vec());
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: msgs[0..1].to_vec(),
            },
            &[],
        )
        .unwrap();

    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs[0..1]
            .iter()
            .map(|m| (m.id(), MessageStatus::Verified))
            .collect::<Vec<(String, MessageStatus)>>()
    );

    // other should not be verified
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: msgs[1..2].to_vec(),
            },
            &[],
        )
        .unwrap();

    let ret: Vec<(String, MessageStatus)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs[1..2]
            .iter()
            .map(|m| (m.id(), MessageStatus::Received))
            .collect::<Vec<(String, MessageStatus)>>()
    );
}

// TODO same ID diff message
// TODO errors from router
