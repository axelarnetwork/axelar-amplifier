use assert_ok::assert_ok;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{migrate_from_version, IntoContractError};
use cosmwasm_std::testing::{mock_dependencies, mock_env};
use cosmwasm_std::{DepsMut, Empty, Env, Response};
use thiserror::Error;

#[derive(Error, Debug, IntoContractError)]
enum TestError {
    #[error("error")]
    Something,
}

#[test]
fn can_convert_error() {
    _ = ContractError::from(TestError::Something);
}

#[migrate_from_version("999.1")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // migration logic
    deps.storage.set(b"key", b"migrated value");
    Ok(Response::default())
}

#[test]
fn should_handle_version_migration() {
    let mut deps = mock_dependencies();

    let base_contract = env!("CARGO_PKG_NAME");
    let base_version = "999.1.1";
    cw2::set_contract_version(deps.as_mut().storage, base_contract, base_version).unwrap();
    deps.as_mut().storage.set(b"key", b"original value");

    migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

    let contract_version = assert_ok!(cw2::get_contract_version(deps.as_ref().storage));
    assert_eq!(contract_version.contract, base_contract);
    assert_eq!(contract_version.version, env!("CARGO_PKG_VERSION"));

    let migrated_value = deps.as_ref().storage.get(b"key").unwrap();
    assert_eq!(migrated_value, b"migrated value")
}

#[test]
#[should_panic(expected = "base version 999.2.1 does not match ~999.1.0 version requirement")]
fn should_fail_version_migration_if_not_supported() {
    let mut deps = mock_dependencies();
    let base_contract = env!("CARGO_PKG_NAME");
    let base_version = "999.2.1";
    cw2::set_contract_version(deps.as_mut().storage, base_contract, base_version).unwrap();

    migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();
}

#[test]
#[should_panic(expected = "contract name mismatch: actual wrong-base-contract, expected ")]
fn should_fail_version_migration_using_wrong_contract() {
    let mut deps = mock_dependencies();
    let base_contract = "wrong-base-contract";
    let base_version = "999.1.1";
    cw2::set_contract_version(deps.as_mut().storage, base_contract, base_version).unwrap();

    migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();
}

#[test]
fn test_single_unnamed_field() {
    use axelar_wasm_std::EventAttributes;
    use axelar_wasm_std_derive::IntoEvent;
    use cosmwasm_std::Event;
    use serde::Serialize;

    #[derive(Serialize, EventAttributes)]
    struct TestStruct {
        field1: u64,
        field2: String,
    }

    #[derive(IntoEvent)]
    enum TestEvents {
        SingleValue(TestStruct),
    }

    let actual: Event = TestEvents::SingleValue(TestStruct {
        field1: 42,
        field2: "test".to_string(),
    })
    .into();
    let expected = Event::new("single_value")
        .add_attribute("field1", "42")
        .add_attribute("field2", "\"test\"");
    assert_eq!(actual, expected);
}

#[test]
fn test_complex_unnamed_field() {
    use std::collections::BTreeMap;

    use axelar_wasm_std::EventAttributes;
    use axelar_wasm_std_derive::IntoEvent;
    use cosmwasm_std::Event;
    use serde::Serialize;

    #[derive(Serialize, EventAttributes)]
    struct ComplexStruct {
        id: String,
        count: u64,
        active: bool,
        tags: Vec<String>,
        metadata: BTreeMap<String, String>,
    }

    #[derive(IntoEvent)]
    enum ComplexEvents {
        ComplexValue(ComplexStruct),
    }

    let actual: Event = ComplexEvents::ComplexValue(ComplexStruct {
        id: "msg-123".to_string(),
        count: 42,
        active: true,
        tags: vec!["important".to_string(), "urgent".to_string()],
        metadata: [("source".to_string(), "api".to_string())]
            .into_iter()
            .collect(),
    })
    .into();

    let expected = Event::new("complex_value")
        .add_attribute("id", "\"msg-123\"")
        .add_attribute("count", "42")
        .add_attribute("active", "true")
        .add_attribute("tags", "[\"important\",\"urgent\"]")
        .add_attribute("metadata", "{\"source\":\"api\"}");

    assert_eq!(actual, expected);
}

#[test]
fn test_multiple_unnamed_fields_should_fail() {
    // This should fail to compile
    // #[derive(IntoEvent)]
    // enum TestEvents {
    //     MultipleValues(u64, String), // This should cause a compilation error
    // }

    // The test passes if this code doesn't compile
    // We can't actually test this in a unit test, but the doc tests verify this behavior
}

#[test]
fn test_primitive_unnamed_field_should_fail() {
    // This should fail to compile
    // #[derive(IntoEvent)]
    // enum TestEvents {
    //     SingleValue(u64), // Primitive types not allowed in unnamed fields
    // }

    // The test passes if this code doesn't compile
    // We can't actually test this in a unit test, but the doc tests verify this behavior
}

#[test]
fn test_hex_attribute_detection() {
    use axelar_wasm_std::EventAttributes;
    use serde::Serialize;

    #[derive(Serialize, EventAttributes)]
    struct TestHexStruct {
        regular_field: String,
        #[serde(with = "axelar_wasm_std::hex")]
        custom_hex_field: [u8; 32],
    }

    let test_struct = TestHexStruct {
        regular_field: "test".to_string(),
        custom_hex_field: [1; 32],
    };

    let mut event = cosmwasm_std::Event::new("test_event");
    test_struct.add_event_attributes(&mut event);

    // Verify that regular_field uses JSON serialization
    let regular_attr = event
        .attributes
        .iter()
        .find(|attr| attr.key == "regular_field")
        .unwrap();
    assert_eq!(regular_attr.value, "\"test\"");

    // Verify that custom_hex_field uses hex serialization
    let hex_attr = event
        .attributes
        .iter()
        .find(|attr| attr.key == "custom_hex_field")
        .unwrap();
    assert_eq!(
        hex_attr.value,
        "\"0101010101010101010101010101010101010101010101010101010101010101\""
    );
}
