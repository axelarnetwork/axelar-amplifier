use std::fmt::{Debug, Display, Formatter};

use cosmwasm_std::{Addr, StdResult};
use cw_storage_plus::Item;
use flagset::{flags, Flags};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::flagset::FlagSet;
use crate::FnExt;

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
    #[error("sender '{actual}' must be one of the addresses {expected:?}")]
    AddressNotWhitelisted { expected: Vec<Addr>, actual: Addr },
    #[error("no whitelisting condition found for sender address '{sender}'")]
    WhitelistNotFound { sender: Addr },
    #[error("specific check called on wrong enum variant")]
    WrongVariant,
    #[error("sender is not authorized")]
    Unauthorized, // generic error to handle errors that don't fall into the above cases
}

const ADMIN: Item<Addr> = Item::new("permission_control_contract_admin_addr");

const GOVERNANCE: Item<Addr> = Item::new("permission_control_governance_addr");

pub fn set_admin(storage: &mut dyn cosmwasm_std::Storage, addr: &Addr) -> StdResult<()> {
    ADMIN.save(storage, addr)
}

pub fn set_governance(storage: &mut dyn cosmwasm_std::Storage, addr: &Addr) -> StdResult<()> {
    GOVERNANCE.save(storage, addr)
}

/// Generally it shouldn't be necessary to call this function directly, use derived permission controlled functions instead
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
    use cosmwasm_std::testing::MockStorage;

    use super::*;

    #[test]
    fn display_permissions() {
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

    #[test]
    fn sender_role_from_storage() {
        let admin = Addr::unchecked("admin");
        let governance = Addr::unchecked("governance");
        let regular_user = Addr::unchecked("regular user");

        let mut storage = MockStorage::new();
        set_admin(&mut storage, &admin).unwrap();
        set_governance(&mut storage, &governance).unwrap();

        assert_eq!(
            sender_role(&storage, &admin).unwrap(),
            FlagSet::from(Permission::Admin)
        );
        assert_eq!(
            sender_role(&storage, &governance).unwrap(),
            FlagSet::from(Permission::Governance)
        );
        assert_eq!(
            sender_role(&storage, &regular_user).unwrap(),
            FlagSet::from(Permission::NoPrivilege)
        );

        set_governance(&mut storage, &admin).unwrap();
        assert_eq!(
            sender_role(&storage, &admin).unwrap(),
            FlagSet::from(Permission::Elevated)
        );
    }

    #[test]
    fn permission_level_correctly_defined() {
        assert!(!FlagSet::from(Permission::NoPrivilege).contains(Permission::Admin));
        assert!(!FlagSet::from(Permission::NoPrivilege).contains(Permission::Governance));

        assert!(!FlagSet::from(Permission::Admin).contains(Permission::NoPrivilege));
        assert!(!FlagSet::from(Permission::Admin).contains(Permission::Governance));

        assert!(!FlagSet::from(Permission::Governance).contains(Permission::NoPrivilege));
        assert!(!FlagSet::from(Permission::Governance).contains(Permission::Admin));

        assert!(!FlagSet::from(Permission::Elevated).contains(Permission::NoPrivilege));
        assert!(FlagSet::from(Permission::Elevated).contains(Permission::Admin));
        assert!(FlagSet::from(Permission::Elevated).contains(Permission::Governance));

        assert!(FlagSet::from(Permission::Any).contains(Permission::NoPrivilege));
        assert!(FlagSet::from(Permission::Any).contains(Permission::Admin));
        assert!(FlagSet::from(Permission::Any).contains(Permission::Governance));
    }
}
