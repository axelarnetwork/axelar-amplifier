use crate::flagset::FlagSet;
use crate::FnExt;
use cosmwasm_std::{Addr, StdResult};
use cw_storage_plus::Item;
use flagset::{flags, Flags};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

flags! {
    #[repr(u8)]
    #[derive(Serialize, Deserialize)]
    pub enum Permission: u8 {
        NoPrivilege = 0b001, // this specifies that the user MUST NOT have an elevated role
        Admin = 0b010,
        Governance = 0b100,
        Elevated = (Permission::Admin | Permission::Governance).bits(),
        Any = (Permission::NoPrivilege | Permission::Elevated).bits(),
    }
}

impl Display for FlagSet<Permission> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Permission::LIST
            .iter()
            .find(|permission| self.eq(&(**permission).into()))
            .map_or_else(
                || {
                    self.into_iter()
                        .map(|permission| format!("{:?}", permission))
                        .join(" | ")
                },
                |permission| format!("{:?}", permission),
            )
            .then(|permission| write!(f, "{}", permission))
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("sender with role '{actual}' is not allowed to perform this action that requires '{expected}' permissions")]
    PermissionDenied {
        expected: FlagSet<Permission>,
        actual: FlagSet<Permission>,
    },
}

/// Ensure that the sender of a message has the correct permissions to perform following actions.
/// Returns an error if not.
/// # Example
/// ```
/// # use cosmwasm_std::testing::mock_dependencies;
/// use cosmwasm_std::Addr;
/// use axelar_wasm_std::ensure_permission;
/// use axelar_wasm_std::permission_control::Permission;
///# use axelar_wasm_std::permission_control::Error;
///
///# fn main() -> Result<(),Box<dyn std::error::Error>>{
///# use axelar_wasm_std::permission_control;
///# let mut deps = mock_dependencies();
///# let deps = deps.as_mut();
/// let admin = Addr::unchecked("admin");
/// let governance = Addr::unchecked("governance");
///
/// // set these before checking permissions
/// permission_control::set_admin(deps.storage, &admin)?;
/// permission_control::set_governance(deps.storage, &governance)?;
///
/// ensure_permission!(Permission::Elevated, deps.storage, &admin);
/// ensure_permission!(Permission::Elevated, deps.storage, &governance);
///
/// do_something();
/// # Ok(())}
///
/// #    fn do_something() {}
/// ```
#[macro_export]
macro_rules! ensure_permission {
    ($permission_variant:expr, $storage:expr, $sender:expr) => {
        let permission = $crate::flagset::FlagSet::from($permission_variant);

        if !permission.contains($crate::permission_control::Permission::Any) {
            let role = error_stack::ResultExt::change_context(
                $crate::permission_control::sender_role($storage, $sender),
                $crate::permission_control::Error::PermissionDenied {
                    expected: permission.clone(),
                    actual: Permission::NoPrivilege.into(),
                },
            )?;

            if (*permission & *role).is_empty() {
                return Err($crate::permission_control::Error::PermissionDenied {
                    expected: permission,
                    actual: role,
                }
                .into());
            }
        }
    };
}

/// This macro should be used as a marker to signify that the call is deliberately without checks
///
/// # Example
/// ```
///# fn main() -> Result<(),Box<dyn std::error::Error>>{
///# use axelar_wasm_std::{ensure_any_permission};
/// ensure_any_permission!();
/// do_something();
/// # Ok(())}
///
/// #    fn do_something() {}
/// ```
#[macro_export]
macro_rules! ensure_any_permission {
    () => {};
}

const ADMIN: Item<Addr> = Item::new("permission_control_contract_admin_addr");

const GOVERNANCE: Item<Addr> = Item::new("permission_control_governance_addr");

pub fn set_admin(storage: &mut dyn cosmwasm_std::Storage, addr: &Addr) -> StdResult<()> {
    ADMIN.save(storage, addr)
}

pub fn set_governance(storage: &mut dyn cosmwasm_std::Storage, addr: &Addr) -> StdResult<()> {
    GOVERNANCE.save(storage, addr)
}

// this is an implementation detail of the macro and shouldn't be called on its own
#[doc(hidden)]
#[allow(clippy::arithmetic_side_effects)] // flagset is safe
pub fn sender_role(
    storage: &dyn cosmwasm_std::Storage,
    sender: &Addr,
) -> StdResult<FlagSet<Permission>> {
    let admin = ADMIN.may_load(storage)?;
    let governance = GOVERNANCE.may_load(storage)?;

    let mut role = FlagSet::from(Permission::NoPrivilege);

    if admin.is_some_and(|admin| admin == sender) {
        *role |= Permission::Admin;
    }

    if governance.is_some_and(|governance| governance == sender) {
        *role |= Permission::Governance;
    }

    // a role cannot be both elevated and without privilege at the same time
    if !role.is_disjoint(Permission::Elevated) {
        *role -= Permission::NoPrivilege;
    }

    Ok(role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockStorage;
    use cosmwasm_std::Addr;
    use error_stack::Report;
    use flagset::Flags;

    #[test]
    fn test_ensure_permission() {
        let no_privilege = Addr::unchecked("regular user");
        let admin = Addr::unchecked("admin");
        let governance = Addr::unchecked("governance");

        let check = |permission, user, storage| {
            ensure_permission!(permission, storage, user);
            Ok::<(), Report<Error>>(())
        };

        // no addresses set: all addresses should be treated as not privileged
        let storage = MockStorage::new();
        for permission in Permission::LIST {
            match permission {
                Permission::NoPrivilege | Permission::Any => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
                // none of these can be called if no addresses are set
                Permission::Admin | Permission::Governance | Permission::Elevated => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
            }
        }

        // admin set: only admin should be allowed to call admin and elevated commands
        let mut storage = MockStorage::new();
        set_admin(&mut storage, &admin).unwrap();

        for permission in Permission::LIST {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_err()); //
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
                Permission::Admin | Permission::Elevated => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                // gov address is not set, so these should all fail
                Permission::Governance => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                Permission::Any => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
            }
        }

        // governance set: only governance should be allowed to call governance and elevated commands
        let mut storage = MockStorage::new();
        set_governance(&mut storage, &governance).unwrap();

        for permission in Permission::LIST {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                // admin address is not set, so these should all fail
                Permission::Admin => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                Permission::Governance | Permission::Elevated => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
                Permission::Any => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
            }
        }

        // admin and governance set: both should be allowed to call admin, governance, and elevated commands
        let mut storage = MockStorage::new();
        set_admin(&mut storage, &admin).unwrap();
        set_governance(&mut storage, &governance).unwrap();

        for permission in Permission::LIST {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                Permission::Admin => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_err());
                }
                Permission::Governance => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_err());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
                Permission::Elevated => {
                    assert!(check(*permission, &no_privilege, &storage).is_err());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
                Permission::Any => {
                    assert!(check(*permission, &no_privilege, &storage).is_ok());
                    assert!(check(*permission, &admin, &storage).is_ok());
                    assert!(check(*permission, &governance, &storage).is_ok());
                }
            }
        }
    }

    #[test]
    fn test() {
        assert_eq!(format!("{}", FlagSet::from(Permission::Admin)), "Admin");
        assert_eq!(
            format!(
                "{}",
                FlagSet::from(Permission::NoPrivilege | Permission::Governance)
            ),
            "NoPrivilege | Governance"
        );
        assert_eq!(
            format!(
                "{}",
                FlagSet::from(Permission::NoPrivilege | Permission::Governance | Permission::Admin)
            ),
            "Any"
        );
    }
}
