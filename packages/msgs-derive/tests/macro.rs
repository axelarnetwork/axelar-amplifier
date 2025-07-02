use std::fmt::Display;

use axelar_wasm_std::permission_control;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::{mock_dependencies, MockApi, MockStorage};
use cosmwasm_std::{Addr, DepsMut, MessageInfo, Storage};
use error_stack::{report, Report};
use msgs_derive::{ensure_permissions, Permissions};

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

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ExecuteError {
    #[error("default error")]
    Default,
}

#[cw_serde]
#[derive(Permissions)]
pub enum TestMsg3 {
    #[permission(Any, Proxy(gateway1))]
    Any,
    #[permission(Elevated, Proxy(gateway1))]
    Proxy1,
    #[permission(Specific(gateway1), Proxy(gateway1))]
    Proxy2,
    #[permission(Any, Proxy(gateway1))]
    Proxy3,
    #[permission(Specific(gateway2), NoPrivilege, Proxy(gateway1, gateway2, gateway3))]
    Proxy4,
    #[permission(Specific(gateway2), Proxy(gateway1))]
    Proxy5,
}

pub fn proxy_permission(
    proxy_name: &str,
) -> impl FnOnce(&dyn Storage) -> error_stack::Result<Addr, axelar_wasm_std::permission_control::Error>
       + '_ {
    move |_| error_stack::Result::Ok(MockApi::default().addr_make(proxy_name))
}

pub fn specific_permission(
    specific_name: &str,
) -> impl FnOnce(
    &dyn Storage,
    &TestMsg3,
) -> error_stack::Result<Addr, axelar_wasm_std::permission_control::Error>
       + '_ {
    move |_, _| error_stack::Result::Ok(MockApi::default().addr_make(specific_name))
}

#[ensure_permissions(proxy(gateway1 = proxy_permission("gateway1"), gateway2 = proxy_permission("gateway2"), gateway3 = proxy_permission("gateway3")), direct(gateway1 = specific_permission("gateway1"), gateway2 = specific_permission("gateway2")))]
pub fn execute(
    deps: DepsMut,
    info: MessageInfo,
    msg: TestMsg3,
) -> error_stack::Result<(), axelar_wasm_std::permission_control::Error> {
    Ok(())
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

#[test]
fn ensure_proxy_permissions() {
    let no_privilege = MockApi::default().addr_make("regular user");
    let admin = MockApi::default().addr_make("admin");
    let governance = MockApi::default().addr_make("governance");

    let gateway1_addr = MockApi::default().addr_make("gateway1");
    let gateway2_addr = MockApi::default().addr_make("gateway2");
    let gateway3_addr = MockApi::default().addr_make("gateway3");

    let mut deps = mock_dependencies();
    permission_control::set_admin(&mut deps.storage, &admin).unwrap();
    permission_control::set_governance(&mut deps.storage, &governance).unwrap();

    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: no_privilege.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Direct(TestMsg3::Any),
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: no_privilege.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: admin.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: governance.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway1_addr.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway2_addr.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway3_addr.clone(),
            msg: TestMsg3::Any
        }
    )
    .is_ok());

    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: no_privilege.clone(),
                msg: TestMsg3::Proxy1
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: admin.clone(),
            msg: TestMsg3::Proxy1
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: governance.clone(),
            msg: TestMsg3::Proxy1
        }
    )
    .is_ok());
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway1_addr.clone(),
                msg: TestMsg3::Proxy1
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway2_addr.clone(),
                msg: TestMsg3::Proxy1
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway3_addr.clone(),
                msg: TestMsg3::Proxy1
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));

    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Direct(TestMsg3::Proxy2),
    )
    .is_ok(),);
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway2_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Direct(TestMsg3::Proxy2),
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: no_privilege.clone(),
                msg: TestMsg3::Proxy2
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: admin.clone(),
                msg: TestMsg3::Proxy2
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy2
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway1_addr.clone(),
            msg: TestMsg3::Proxy2
        }
    )
    .is_ok());
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway2_addr.clone(),
                msg: TestMsg3::Proxy2
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway3_addr.clone(),
                msg: TestMsg3::Proxy2
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));

    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: governance.clone(),
            msg: TestMsg3::Proxy3
        }
    )
    .is_ok());
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway2_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy3
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::Unauthorized
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway3_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy3
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::Unauthorized
    ));

    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway2_addr.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway2_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway2_addr.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway3_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: gateway2_addr.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());

    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway1_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: no_privilege.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway2_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: no_privilege.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());
    assert!(execute(
        deps.as_mut(),
        MessageInfo {
            sender: gateway3_addr.clone(),
            funds: vec![]
        },
        TestMsg3FromProxy::Relay {
            sender: no_privilege.clone(),
            msg: TestMsg3::Proxy4
        }
    )
    .is_ok());

    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy4
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway2_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy4
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway3_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: governance.clone(),
                msg: TestMsg3::Proxy4
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::PermissionDenied { .. }
    ));

    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway1_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway1_addr.clone(),
                msg: TestMsg3::Proxy5
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::AddressNotWhitelisted { .. }
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway2_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway2_addr.clone(),
                msg: TestMsg3::Proxy5
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::Unauthorized
    ));
    assert!(matches!(
        execute(
            deps.as_mut(),
            MessageInfo {
                sender: gateway3_addr.clone(),
                funds: vec![]
            },
            TestMsg3FromProxy::Relay {
                sender: gateway3_addr.clone(),
                msg: TestMsg3::Proxy5
            }
        )
        .unwrap_err()
        .current_context(),
        permission_control::Error::Unauthorized
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
