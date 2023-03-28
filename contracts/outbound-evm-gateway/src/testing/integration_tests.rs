use crate::testing::utils::{
    executes::{finalize_actions, post_worker_reply},
    setup::{default_instantiation_message, default_pub_keys, WORKERS},
    utils::get_event_attribute_value,
};
use cosmwasm_std::{Attribute, Binary, Uint64};
use secp256k1::{sign, Message};

use super::utils::{
    executes::request_worker_action,
    setup::{default_keys, setup_test_case},
    utils::{get_event, get_event_attribute},
};

#[test]
fn test_request_worker_action() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let sig_id = Uint64::one();
    let key_id = Uint64::one();
    let destination_chain = default_instantiation_message()
        .outbound_settings
        .destination_chain_name;

    let res = request_worker_action(&mut app, service_addr).unwrap();

    let sig_started_event = get_event(&res, "wasm-SigningStarted");
    let sign_event = get_event(&res, "wasm-Sign");

    assert!(sig_started_event.is_some());
    let sig_started_event = sig_started_event.unwrap();
    let sig_started_attributes = &sig_started_event.attributes;

    let mut expected_keys: Vec<Binary> = default_pub_keys()
        .into_iter()
        .map(|item| {
            let (_, pub_key) = item;
            pub_key
        })
        .collect();
    expected_keys.sort();

    let mut found_keys: Vec<Binary> =
        get_event_attribute_value(sig_started_event, "pub_keys").unwrap();
    found_keys.sort();

    assert!(sig_started_attributes.contains(&Attribute::new("sig_id", sig_id)));
    assert!(sig_started_attributes.contains(&Attribute::new("key_id", key_id)));
    assert_eq!(found_keys, expected_keys);
    assert_eq!(
        get_event_attribute(sig_started_event, "payload_hash").is_some(),
        true
    );

    assert!(sign_event.is_some());
    let sign_event = sign_event.unwrap();

    let sign_attributes = &sign_event.attributes;
    assert!(sign_attributes.contains(&Attribute::new("chain", destination_chain)));
    assert_eq!(get_event_attribute(sign_event, "batch_id").is_some(), true);
    assert_eq!(
        get_event_attribute(sign_event, "commands_ids").is_some(),
        true
    );
}

#[test]
fn test_post_worker_reply() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let sig_id = Uint64::one();

    let request_res = request_worker_action(&mut app, service_addr.clone()).unwrap();
    let sig_started_event = get_event(&request_res, "wasm-SigningStarted").unwrap();

    let payload_hash_str = get_event_attribute(sig_started_event, "payload_hash").unwrap();
    let mut payload_hash = [0u8; 32];
    hex::decode_to_slice(payload_hash_str, &mut payload_hash).unwrap();
    let message = Message::parse(&payload_hash);

    let keys = default_keys();
    let (secret_key, _) = keys.get(WORKERS[0]).unwrap();
    let (signature, _) = sign(&message, secret_key);
    let signature: Binary = signature.serialize_der().as_ref().into();

    let res = post_worker_reply(
        &mut app,
        WORKERS[0],
        service_addr,
        sig_id,
        signature.clone(),
    )
    .unwrap();

    let event = get_event(&res, "wasm-SignatureSubmitted");
    assert!(event.is_some());
    let event = event.unwrap();

    let attributes = &event.attributes;
    assert!(attributes.contains(&Attribute::new("sig_id", sig_id)));
    assert!(attributes.contains(&Attribute::new("participant", WORKERS[0])));
    assert!(attributes.contains(&Attribute::new("signature", signature.to_base64())));
}

#[test]
fn test_finalize_actions() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let sig_id = Uint64::one();

    let request_res = request_worker_action(&mut app, service_addr.clone()).unwrap();
    let sig_started_event = get_event(&request_res, "wasm-SigningStarted").unwrap();

    let payload_hash_str = get_event_attribute(sig_started_event, "payload_hash").unwrap();
    let mut payload_hash = [0u8; 32];
    hex::decode_to_slice(payload_hash_str, &mut payload_hash).unwrap();
    let message = Message::parse(&payload_hash);

    let keys = default_keys();

    for worker in WORKERS {
        let (secret_key, _) = keys.get(worker).unwrap();
        let (signature, _) = sign(&message, secret_key);
        let signature: Binary = signature.serialize_der().as_ref().into();

        post_worker_reply(&mut app, worker, service_addr.clone(), sig_id, signature).unwrap();
    }

    app.update_block(|block| {
        block.time = block.time.plus_seconds(25);
        block.height += 5;
    });

    let res = finalize_actions(&mut app, service_addr).unwrap();
    let event = get_event(&res, "wasm-SigningCompleted");
    assert!(event.is_some());

    let attributes = &event.unwrap().attributes;
    assert!(attributes.contains(&Attribute::new("sig_id", sig_id)));
}
