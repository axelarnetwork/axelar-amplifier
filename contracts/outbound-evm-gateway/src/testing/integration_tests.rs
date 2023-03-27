use crate::testing::utils::setup::default_pub_keys;
use cosmwasm_std::{Attribute, Binary, Uint64};

use super::utils::{executes::request_worker_action, setup::setup_test_case};

#[test]
fn test_request_worker_action() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let sig_id = Uint64::one();
    let key_id = Uint64::one();

    let res = request_worker_action(&mut app, service_addr).unwrap();

    let sig_started_event = res
        .events
        .iter()
        .find(|event| event.ty == "wasm-SigningStarted");

    let sign_event = res.events.iter().find(|event| event.ty == "wasm-Sign");

    assert!(sig_started_event.is_some());
    let sig_started_attributes = &sig_started_event.unwrap().attributes;

    let mut expected_keys: Vec<Binary> = default_pub_keys()
        .into_iter()
        .map(|item| {
            let (_, pub_key) = item;
            pub_key
        })
        .collect();
    expected_keys.sort();

    let pub_keys_attribute = sig_started_attributes
        .iter()
        .find(|attr| attr.key == "pub_keys")
        .unwrap();
    let mut found_keys =
        serde_json::from_str::<Vec<Binary>>(pub_keys_attribute.value.as_str()).unwrap();
    found_keys.sort();

    assert!(sig_started_attributes.contains(&Attribute::new("sig_id", sig_id)));
    assert!(sig_started_attributes.contains(&Attribute::new("key_id", key_id)));
    assert_eq!(found_keys, expected_keys);
    assert_eq!(
        sig_started_attributes
            .iter()
            .find(|attr| attr.key == "payload_hash")
            .is_some(),
        true
    );

    assert!(sign_event.is_some());
}
