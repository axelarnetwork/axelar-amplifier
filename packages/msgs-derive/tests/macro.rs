use axelar_wasm_std::permission_control;
use cosmwasm_std::testing::MockStorage;
use cosmwasm_std::Addr;

#[derive(msgs_derive::EnsurePermissions, Clone)]
#[allow(dead_code)] // the msg field are only defined to make sure the derive can handle fields correctly
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
}

#[test]
fn test_ensure_permission() {
    let no_privilege = Addr::unchecked("regular user");
    let admin = Addr::unchecked("admin");
    let governance = Addr::unchecked("governance");

    let mut storage = MockStorage::new();
    permission_control::set_admin(&mut storage, &admin).unwrap();
    permission_control::set_governance(&mut storage, &governance).unwrap();

    assert!(TestMsg::NoPrivilege
        .ensure_permission(&storage, &no_privilege)
        .is_ok());
    assert!(TestMsg::NoPrivilege
        .ensure_permission(&storage, &admin)
        .is_err());
    assert!(TestMsg::NoPrivilege
        .ensure_permission(&storage, &governance)
        .is_err());

    assert!(TestMsg::Admin
        .ensure_permission(&storage, &no_privilege)
        .is_err());
    assert!(TestMsg::Admin.ensure_permission(&storage, &admin).is_ok());
    assert!(TestMsg::Admin
        .ensure_permission(&storage, &governance)
        .is_err());

    assert!(TestMsg::Governance
        .ensure_permission(&storage, &no_privilege)
        .is_err());
    assert!(TestMsg::Governance
        .ensure_permission(&storage, &admin)
        .is_err());
    assert!(TestMsg::Governance
        .ensure_permission(&storage, &governance)
        .is_ok());

    assert!(TestMsg::Any { test: 0 }
        .ensure_permission(&storage, &no_privilege)
        .is_ok());
    assert!(TestMsg::Any { test: 0 }
        .ensure_permission(&storage, &admin)
        .is_ok());
    assert!(TestMsg::Any { test: 0 }
        .ensure_permission(&storage, &governance)
        .is_ok());

    assert!(TestMsg::Elevated(true)
        .ensure_permission(&storage, &no_privilege)
        .is_err());
    assert!(TestMsg::Elevated(true)
        .ensure_permission(&storage, &admin)
        .is_ok());
    assert!(TestMsg::Elevated(true)
        .ensure_permission(&storage, &governance)
        .is_ok());
}
