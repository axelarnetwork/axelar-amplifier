use std::fmt;
use std::hash::{Hash as StdHash, Hasher};
use std::str::FromStr;

use cosmrs::AccountId;
use deref_derive::Deref;
use ethers_core::types::{Address, H256};
use serde::{Deserialize, Serialize};

mod key;
pub(crate) mod starknet;
#[cfg(test)]
pub use key::test_utils::random_cosmos_public_key;
pub use key::{CosmosPublicKey, PublicKey};

pub type EVMAddress = Address;
pub type Hash = H256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref)]
pub struct TMAddress(AccountId);

impl FromStr for TMAddress {
    type Err = <AccountId as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AccountId::from_str(s).map(Self)
    }
}

impl StdHash for TMAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl From<AccountId> for TMAddress {
    fn from(account_id: AccountId) -> Self {
        Self(account_id)
    }
}

impl AsRef<AccountId> for TMAddress {
    fn as_ref(&self) -> &AccountId {
        &self.0
    }
}

impl fmt::Display for TMAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::key::test_utils::random_cosmos_public_key;
    use crate::types::TMAddress;

    impl TMAddress {
        pub fn random(prefix: &str) -> Self {
            Self(
                random_cosmos_public_key()
                    .account_id(prefix)
                    .expect("failed to convert to account identifier"),
            )
        }
    }
}
