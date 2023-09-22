use std::collections::HashSet;

use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use connection_router::state::{CrossChainId, NewMessage, ID_SEPARATOR};
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

    let msg = generate_messages(1).swap_remove(0);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![]),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.cc_id.clone(), false)]);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.cc_id.clone(), false)]);

    mark_messages_as_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.cc_id.clone(), true)]);

    // should still return true if queried again
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(vec![msg.clone()]),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), vec![msg.clone()]);
    assert_eq!(ret, vec![(msg.cc_id, true)]);
}

fn generate_messages(count: usize) -> Vec<NewMessage> {
    let mut msgs = vec![];
    for x in 0..count {
        msgs.push(NewMessage {
            cc_id: CrossChainId {
                chain: "mock-chain".parse().unwrap(),
                id: format!("{}{}{}", "hash", ID_SEPARATOR, x).parse().unwrap(),
            },
            destination_address: "idc".parse().unwrap(),
            destination_chain: "mock-chain-2".parse().unwrap(),
            source_address: "idc".parse().unwrap(),
            payload_hash: vec![x as u8, 0, 0, 0].into(),
        })
    }
    msgs
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
        &ExecuteMsg::VerifyMessages(msgs.clone()),
        &[],
    );

    assert!(res.is_ok());

    let ret = is_verified(
        &mut app,
        verifier_address.clone(),
        msgs.iter()
            .map(|msg| msg.clone().try_into().unwrap())
            .collect(),
    );

    let msg_id_set: HashSet<_> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();
    let (_, unverified) = partition_by_verified(&ret);
    assert_eq!(msg_id_set, unverified);

    mark_messages_as_verified(
        &mut app,
        verifier_address.clone(),
        msgs.iter().map(|msg| msg.clone()).collect(),
    );

    for _ in 0..2 {
        let res = app.execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages(msgs.clone()),
            &[],
        );
        assert!(res.is_ok());

        let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
        let (verified, _) = partition_by_verified(&ret);
        assert_eq!(msg_id_set, verified);
    }
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
    let expected_verified: HashSet<_> = msgs_verified.iter().map(|msg| msg.cc_id.clone()).collect();
    let expected_unverified: HashSet<_> = msgs_unverified
        .iter()
        .map(|msg| msg.cc_id.clone())
        .collect();

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs_verified.to_vec());

    // same call should return same response
    for _ in 0..2 {
        let res = app.execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages(msgs.clone()),
            &[],
        );
        assert!(res.is_ok());

        let mut ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
        let (verified, unverified) = partition_by_verified(&mut ret);
        assert_eq!(expected_verified, verified);
        assert_eq!(expected_unverified, unverified);
    }

    // mark the rest as verified
    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs_unverified.to_vec());
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let mut ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    let (verified, unverified) = partition_by_verified(&mut ret);
    assert!(unverified.is_empty());
    assert_eq!(
        msgs.into_iter()
            .map(|msg| msg.cc_id)
            .collect::<HashSet<_>>(),
        verified
    );
}

fn partition_by_verified(
    ret: &Vec<(CrossChainId, bool)>,
) -> (HashSet<CrossChainId>, HashSet<CrossChainId>) {
    let verified: HashSet<_> = ret
        .into_iter()
        .filter_map(|(id, verified)| if *verified { Some(id.clone()) } else { None })
        .collect();
    let unverified: HashSet<_> = ret
        .into_iter()
        .filter_map(|(id, verified)| if !*verified { Some(id.clone()) } else { None })
        .collect();

    (verified, unverified)
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
        &ExecuteMsg::VerifyMessages(
            msgs.iter()
                .map(|msg| msg.clone().try_into().unwrap())
                .collect(),
        ),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), false))
            .collect::<Vec<_>>()
    );

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs.clone());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    let ret = get_router_messages(&mut app, router_address, msgs.clone());
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
    let expected_messages: HashSet<_> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let mut ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    let (verified, unverified) = partition_by_verified(&mut ret);
    assert!(verified.is_empty());
    assert_eq!(expected_messages, unverified);

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs.clone());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());
    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    let (verified, unverified) = partition_by_verified(&ret);
    assert!(unverified.is_empty());
    assert_eq!(expected_messages, verified);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    let (verified, unverified) = partition_by_verified(&ret);
    assert!(unverified.is_empty());
    assert_eq!(expected_messages, verified);

    let ret = get_router_messages(&mut app, router_address, msgs.clone());
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
    let expected_verified: HashSet<_> = msgs_verified.iter().map(|msg| msg.cc_id.clone()).collect();
    let expected_unverified: HashSet<_> = msgs_unverified
        .iter()
        .map(|msg| msg.cc_id.clone())
        .collect();

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs_verified.to_vec());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let mut ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    let (verified, unverified) = partition_by_verified(&mut ret);
    assert_eq!(expected_verified, verified);
    assert_eq!(expected_unverified, unverified);

    let ret = get_router_messages(&mut app, router_address.clone(), msgs_verified.to_vec());
    assert_eq!(ret, msgs_verified);
    let ret = get_router_messages(&mut app, router_address, msgs_unverified.to_vec());
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
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), false))
            .collect::<Vec<_>>()
    );

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs.clone());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    let ret = get_router_messages(&mut app, router_address, msgs.clone());
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

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs.clone());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    let ret = get_router_messages(&mut app, router_address, msgs.clone());
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

    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs.clone());

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    let ret = get_router_messages(&mut app, router_address, msgs.clone());
    assert_eq!(ret, msgs);

    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs.clone());
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
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
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<NewMessage> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|msg| msg.cc_id.clone()).collect(),
            },
        )
        .unwrap();
    assert_eq!(ret, msgs);
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
        &ExecuteMsg::RouteMessages(msgs.clone()),
        &[],
    );
    assert!(res.is_ok());

    let ret: Vec<NewMessage> = app
        .wrap()
        .query_wasm_smart(
            gateway_address,
            &QueryMsg::GetMessages {
                message_ids: msgs.iter().map(|msg| msg.cc_id.clone()).collect(),
            },
        )
        .unwrap();
    assert_eq!(ret, msgs);
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
    let mut msgs = generate_messages(2);
    msgs[1].cc_id.id = msgs[0].cc_id.id.clone();
    assert_ne!(msgs[0], msgs[1]);

    let err = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::VerifyMessages(msgs.clone()),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        err.downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::DuplicateMessageID).to_string()
    );

    let err = app
        .execute_contract(
            Addr::unchecked("relayer"),
            gateway_address.clone(),
            &ExecuteMsg::RouteMessages(msgs.clone()),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        err.downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::DuplicateMessageID).to_string()
    );

    //verify one of them
    mark_messages_as_verified(&mut app, verifier_address.clone(), msgs[0..1].to_vec());
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs[0..1].to_vec()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs[0..1].to_vec());
    assert_eq!(
        ret,
        msgs[0..1]
            .iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<_>>()
    );

    // other should not be verified
    let res = app.execute_contract(
        Addr::unchecked("relayer"),
        gateway_address.clone(),
        &ExecuteMsg::VerifyMessages(msgs[1..2].to_vec()),
        &[],
    );
    assert!(res.is_ok());

    let ret = is_verified(&mut app, verifier_address.clone(), msgs[1..2].to_vec());
    assert_eq!(
        ret,
        msgs[1..2]
            .iter()
            .map(|msg| (msg.cc_id.clone(), false))
            .collect::<Vec<_>>()
    );
}
