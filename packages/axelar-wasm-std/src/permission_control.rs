use crate::flagset::FlagSet;
use cosmwasm_std::{Addr, StdResult};
use cw_storage_plus::Item;
use flagset::flags;
use serde::{Deserialize, Serialize};

flags! {
    #[repr(u8)]
    #[derive(Serialize, Deserialize)]
    pub enum Permission: u8 {
        NoPrivilege = 1, // this specifies that the user MUST NOT have an elevated role
        Admin = 2,
        Governance = 4,
        Elevated = (Permission::Admin | Permission::Governance).bits(),
        Any = (Permission::NoPrivilege | Permission::Elevated).bits(),
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("sender is not allowed to perform this action")]
    PermissionDenied,
}

#[macro_export]
macro_rules! ensure_permission {
    ($permission_variant:expr, $storage:expr, $sender:expr) => {{
        let permission = $crate::flagset::FlagSet::from($permission_variant);
        if !permission.contains($crate::permission_control::Permission::Any)
            && (*permission
                & *(error_stack::ResultExt::change_context(
                    $crate::permission_control::sender_role($storage, $sender),
                    $crate::permission_control::Error::PermissionDenied,
                ))?)
            .is_empty()
        {
            return Err($crate::permission_control::Error::PermissionDenied.into());
        }
    }};
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

    fn permissions() -> Vec<Permission> {
        let permissions = vec![
            Permission::NoPrivilege,
            Permission::Admin,
            Permission::Governance,
            Permission::Elevated,
            Permission::Any,
        ];

        let mut count = 0;

        for permission in permissions.iter() {
            match permission {
                Permission::NoPrivilege
                | Permission::Admin
                | Permission::Governance
                | Permission::Elevated
                | Permission::Any => count += 1,
            }
        }

        assert_eq!(count, permissions.len());
        permissions
    }

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
        for permission in permissions() {
            match permission {
                Permission::NoPrivilege | Permission::Any => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
                // none of these can be called if no addresses are set
                Permission::Admin | Permission::Governance | Permission::Elevated => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_err());
                }
            }
        }

        // admin set: only admin should be allowed to call admin and elevated commands
        let mut storage = MockStorage::new();
        set_admin(&mut storage, &admin).unwrap();

        for permission in permissions() {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_err()); //
                    assert!(check(permission, &governance, &storage).is_ok());
                }
                Permission::Admin | Permission::Elevated => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                // gov address is not set, so these should all fail
                Permission::Governance => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                Permission::Any => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
            }
        }

        // governance set: only governance should be allowed to call governance and elevated commands
        let mut storage = MockStorage::new();
        set_governance(&mut storage, &governance).unwrap();

        for permission in permissions() {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                // admin address is not set, so these should all fail
                Permission::Admin => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                Permission::Governance | Permission::Elevated => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
                Permission::Any => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
            }
        }

        // admin and governance set: both should be allowed to call admin, governance, and elevated commands
        let mut storage = MockStorage::new();
        set_admin(&mut storage, &admin).unwrap();
        set_governance(&mut storage, &governance).unwrap();

        for permission in permissions() {
            match permission {
                Permission::NoPrivilege => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                Permission::Admin => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_err());
                }
                Permission::Governance => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_err());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
                Permission::Elevated => {
                    assert!(check(permission, &no_privilege, &storage).is_err());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
                Permission::Any => {
                    assert!(check(permission, &no_privilege, &storage).is_ok());
                    assert!(check(permission, &admin, &storage).is_ok());
                    assert!(check(permission, &governance, &storage).is_ok());
                }
            }
        }
    }
}
