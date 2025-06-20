use std::fmt::Display;

use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::{MockApi, MockStorage};
use cosmwasm_std::{Addr, Storage};
use error_stack::{report, Report};
use msgs_derive::Permissions;

#[cw_serde]
#[derive(Permissions)]
#[allow(dead_code)] // the msg fields are only defined to make sure the derive attribute can handle fields correctly
enum TestMsg {
    #[permission(NoPrivilege)]
    NoPrivilege,
    #[permission(Admin)]
    Admin,
    #[permission(Governance)]
    Governance,
    #[permission(Any)]
    Any { test: u8 },
    #[permission(Elevated)]
    Elevated(bool),
    #[permission(Admin, NoPrivilege)]
    Multi,
}

#[cw_serde]
#[derive(Permissions)]
enum TestMsg2 {
    #[permission(Any)]
    Any,
    #[permission(Specific(gateway1))]
    Specific1,
    #[permission(Elevated, Specific(gateway1))]
    Specific2,
    #[permission(Admin, Specific(gateway1), Specific(gateway2), NoPrivilege)]
    Specific3,
    #[permission(Specific(gateway1, gateway2, gateway3))]
    Specific4,
}

#[test]
fn test_general_ensure_permission() {
    let no_privilege = MockApi::default().addr_make("regular user");
    let admin = MockApi::default().addr_make("admin");
    let governance = MockApi::default().addr_make("governance");

    let mut storage = MockStorage::new();
    permission_control::set_admin(&mut storage, &admin).unwrap();
    permission_control::set_governance(&mut storage, &governance).unwrap();

    assert!(TestMsg::NoPrivilege
        .ensure_permissions(&storage, &no_privilege)
        .is_ok());
    assert!(matches!(
        TestMsg::NoPrivilege
            .ensure_permissions(&storage, &admin)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        TestMsg::NoPrivilege
            .ensure_permissions(&storage, &governance)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));

    assert!(matches!(
        TestMsg::Admin
            .ensure_permissions(&storage, &no_privilege)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(TestMsg::Admin.ensure_permissions(&storage, &admin).is_ok());
    assert!(matches!(
        TestMsg::Admin
            .ensure_permissions(&storage, &governance)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));

    assert!(matches!(
        TestMsg::Governance
            .ensure_permissions(&storage, &no_privilege)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        TestMsg::Governance
            .ensure_permissions(&storage, &admin)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(TestMsg::Governance
        .ensure_permissions(&storage, &governance)
        .is_ok());

    assert!(TestMsg::Any { test: 0 }
        .ensure_permissions(&storage, &no_privilege)
        .is_ok());
    assert!(TestMsg::Any { test: 0 }
        .ensure_permissions(&storage, &admin)
        .is_ok());
    assert!(TestMsg::Any { test: 0 }
        .ensure_permissions(&storage, &governance)
        .is_ok());

    assert!(matches!(
        TestMsg::Elevated(true)
            .ensure_permissions(&storage, &no_privilege)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(TestMsg::Elevated(true)
        .ensure_permissions(&storage, &admin)
        .is_ok());
    assert!(TestMsg::Elevated(true)
        .ensure_permissions(&storage, &governance)
        .is_ok());

    assert!(TestMsg::Multi
        .ensure_permissions(&storage, &no_privilege)
        .is_ok());
    assert!(TestMsg::Multi.ensure_permissions(&storage, &admin).is_ok());
    assert!(matches!(
        TestMsg::Multi
            .ensure_permissions(&storage, &governance)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
}

#[test]
fn ensure_specific_permissions() {
    let no_privilege = MockApi::default().addr_make("regular user");
    let admin = MockApi::default().addr_make("admin");
    let governance = MockApi::default().addr_make("governance");

    let gateway1_addr = MockApi::default().addr_make("gateway1");
    let gateway2_addr = MockApi::default().addr_make("gateway2");
    let gateway3_addr = MockApi::default().addr_make("gateway3");

    let gateway1 = |_: &dyn Storage, _: &TestMsg2| {
        Ok::<Addr, Report<Error>>(MockApi::default().addr_make("gateway1"))
    };
    let gateway2 = |_: &dyn Storage, _: &TestMsg2| {
        Ok::<Addr, Report<Error>>(MockApi::default().addr_make("gateway2"))
    };
    let gateway3 = |_: &dyn Storage, _: &TestMsg2| {
        Ok::<Addr, Report<Error>>(MockApi::default().addr_make("gateway3"))
    };

    // Given a set of specific permissions, the Permissions macro will now determine
    // a deterministic order of how the permission checking functions should appear as
    // arguments in 'ensure_permissions'. Previously, the developer was responsible for
    // calling ensure_permissions. Since the call to ensure premissions is now generated,
    // this deterministic ordering helps to ensure arguments are inserted in the correct
    // order.
    // The order in this test happens to be: gateway1, gateway2, gateway3

    let mut storage = MockStorage::new();
    permission_control::set_admin(&mut storage, &admin).unwrap();
    permission_control::set_governance(&mut storage, &governance).unwrap();

    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &no_privilege, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &admin, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &governance, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &gateway1_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &gateway2_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Any
        .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
        .is_ok());

    assert!(matches!(
        TestMsg2::Specific1
            .ensure_permissions(&storage, &no_privilege, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific1
            .ensure_permissions(&storage, &admin, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific1
            .ensure_permissions(&storage, &governance, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(TestMsg2::Specific1
        .ensure_permissions(&storage, &gateway1_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(matches!(
        TestMsg2::Specific1
            .ensure_permissions(&storage, &gateway2_addr, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific1
            .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));

    assert!(matches!(
        TestMsg2::Specific2
            .ensure_permissions(&storage, &no_privilege, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(TestMsg2::Specific2
        .ensure_permissions(&storage, &admin, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific2
        .ensure_permissions(&storage, &governance, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific2
        .ensure_permissions(&storage, &gateway1_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(matches!(
        TestMsg2::Specific2
            .ensure_permissions(&storage, &gateway2_addr, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific2
            .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));

    assert!(TestMsg2::Specific3
        .ensure_permissions(&storage, &no_privilege, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific3
        .ensure_permissions(&storage, &admin, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(matches!(
        TestMsg2::Specific3
            .ensure_permissions(&storage, &governance, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(TestMsg2::Specific3
        .ensure_permissions(&storage, &gateway1_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific3
        .ensure_permissions(&storage, &gateway2_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific3
        .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
        .is_ok()); // because of NoPrivilege

    assert!(matches!(
        TestMsg2::Specific4
            .ensure_permissions(&storage, &no_privilege, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific4
            .ensure_permissions(&storage, &admin, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        TestMsg2::Specific4
            .ensure_permissions(&storage, &governance, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(TestMsg2::Specific4
        .ensure_permissions(&storage, &gateway1_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific4
        .ensure_permissions(&storage, &gateway2_addr, gateway1, gateway2, gateway3)
        .is_ok());
    assert!(TestMsg2::Specific4
        .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
        .is_ok());

    let gateway3 = |_: &dyn Storage, _: &TestMsg2| Err(report!(Error));

    assert!(matches!(
        TestMsg2::Specific4
            .ensure_permissions(&storage, &gateway3_addr, gateway1, gateway2, gateway3)
            .unwrap_err()
            .current_context(),
        permission_control::Error::WhitelistNotFound { .. }
    ));
}

#[derive(Debug)]
struct Error;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error")
    }
}
