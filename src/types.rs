use std::fmt;
use std::hash::{Hash as StdHash, Hasher};

use cosmrs::AccountId;
use ethers::types::{Address, H256};
use serde::{Deserialize, Serialize};

pub type EVMAddress = Address;
pub type Hash = H256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TMAddress(AccountId);

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

impl From<&TMAddress> for AccountId {
    fn from(tm_address: &TMAddress) -> Self {
        tm_address.clone().0
    }
}

impl fmt::Display for TMAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
