use assert_ok::assert_ok;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::migrate_from_version;
use axelar_wasm_std::IntoContractError;
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
#[should_panic(expected = "cannot migrate from wrong-base-contract contract")]
fn should_fail_version_migration_using_wrong_contract() {
    let mut deps = mock_dependencies();
    let base_contract = "wrong-base-contract";
    let base_version = "999.1.1";
    cw2::set_contract_version(deps.as_mut().storage, base_contract, base_version).unwrap();

    migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();
}
