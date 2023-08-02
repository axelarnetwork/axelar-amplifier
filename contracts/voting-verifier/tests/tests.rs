use cosmwasm_std::{from_binary, Addr, Uint64};
use cw_multi_test::{App, ContractWrapper, Executor};

use axelar_wasm_std::Threshold;
use connection_router::msg::Message;
use connection_router::types::ID_SEPARATOR;
use voting_verifier::{contract, error::ContractError, msg};

use crate::mock::make_mock_service_registry;

pub mod mock;

const SENDER: &str = "sender";
const SOURCE_CHAIN: &str = "source_chain";

fn initialize_contract(app: &mut App, service_registry_address: String) -> Addr {
    let msg = msg::InstantiateMsg {
        service_registry_address,
        service_name: "service_name".to_string(),
        voting_threshold: Threshold::try_from((1u64, 2u64)).unwrap(),
        block_expiry: 100,
        confirmation_height: 100,
        source_gateway_address: "gateway_address".to_string(),
    };

    let code = ContractWrapper::new(contract::execute, contract::instantiate, contract::query);
    let code_id = app.store_code(Box::new(code));

    let address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked(SENDER),
            &msg,
            &[],
            "voting-verifier",
            None,
        )
        .unwrap();

    address
}

fn message_id(source_chain: &str, id: &str, index: u64) -> String {
    format!("{source_chain}{ID_SEPARATOR}{id}{ID_SEPARATOR}{index}")
}

fn messages(len: u64) -> Vec<Message> {
    (0..len)
        .map(|i| Message {
            id: message_id(SOURCE_CHAIN, format!("id{i}").as_str(), 0),
            source_chain: SOURCE_CHAIN.to_string(),
            source_address: format!("source_address{i}"),
            destination_chain: format!("destination_chain{i}"),
            destination_address: format!("destination_address{i}"),
            payload_hash: vec![0, 0, 0, 0].into(),
        })
        .collect()
}

#[test]
fn should_failed_if_messages_are_not_from_same_source() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address = initialize_contract(&mut app, service_registry_address.into_string());

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: vec![
            Message {
                id: message_id(SOURCE_CHAIN, "id1", 0),
                source_chain: SOURCE_CHAIN.to_string(),
                source_address: "source_address1".to_string(),
                destination_chain: "destination_chain1".to_string(),
                destination_address: "destination_address1".to_string(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
            Message {
                id: message_id("other_chain", "id2", 0),
                source_chain: "other_chain".to_string(),
                source_address: "source_address2".to_string(),
                destination_chain: "destination_chain2".to_string(),
                destination_address: "destination_address2".to_string(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
        ],
    };

    let err = app
        .execute_contract(Addr::unchecked(SENDER), contract_address, &msg, &[])
        .unwrap_err();
    assert_eq!(
        ContractError::SourceChainMismatch(SOURCE_CHAIN.parse().unwrap()),
        err.downcast().unwrap()
    );
}

#[test]
fn should_verify_messages_if_not_verified() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address = initialize_contract(&mut app, service_registry_address.into_string());

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: vec![
            Message {
                id: message_id(SOURCE_CHAIN, "id1", 0),
                source_chain: SOURCE_CHAIN.to_string(),
                source_address: "source_address1".to_string(),
                destination_chain: "destination_chain1".to_string(),
                destination_address: "destination_address1".to_string(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
            Message {
                id: message_id(SOURCE_CHAIN, "id2", 0),
                source_chain: SOURCE_CHAIN.to_string(),
                source_address: "source_address2".to_string(),
                destination_chain: "destination_chain2".to_string(),
                destination_address: "destination_address2".to_string(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
        ],
    };

    let res = app
        .execute_contract(Addr::unchecked(SENDER), contract_address, &msg, &[])
        .unwrap();
    let reply: msg::VerifyMessagesResponse = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(reply.verification_statuses.len(), 2);
    assert_eq!(
        reply.verification_statuses,
        vec![
            ("source_chain:id1:0".to_string(), false),
            ("source_chain:id2:0".to_string(), false)
        ]
    );
}

#[test]
fn should_query_message_statuses() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address = initialize_contract(&mut app, service_registry_address.into_string());

    let messages = messages(10);

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages.clone(),
    };

    let res = app
        .execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    let reply: msg::VerifyMessagesResponse = from_binary(&res.data.unwrap()).unwrap();

    assert_eq!(reply.verification_statuses.len(), messages.len());
    assert_eq!(
        reply.verification_statuses,
        messages
            .iter()
            .map(|message| (message.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    let query = msg::QueryMsg::IsVerified {
        messages: messages.clone(),
    };

    let statuses: Vec<(String, bool)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .map(|message| (message.id.to_string(), false))
            .collect::<Vec<(String, bool)>>()
    );

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::Vote {
        poll_id: Uint64::one().into(),
        votes: (0..messages.len())
            .map(|i| i % 2 == 0)
            .collect::<Vec<bool>>(),
    };

    app.execute_contract(
        Addr::unchecked("addr1"),
        contract_address.clone(),
        &msg,
        &[],
    )
    .unwrap();
    app.execute_contract(
        Addr::unchecked("addr2"),
        contract_address.clone(),
        &msg,
        &[],
    )
    .unwrap();

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::EndPoll {
        poll_id: Uint64::one().into(),
    };
    app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    let statuses: Vec<(String, bool)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .enumerate()
            .map(|(i, message)| (message.id.to_string(), i % 2 == 0))
            .collect::<Vec<(String, bool)>>()
    );
}
