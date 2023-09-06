use std::fmt;
use std::hash::{Hash as StdHash, Hasher};

use cosmrs::crypto;
use cosmrs::AccountId;
use cosmwasm_std::Uint256;
use ethers::types::{Address, H256};
use serde::{Deserialize, Serialize};

pub type EVMAddress = Address;
pub type Hash = H256;
pub type PublicKey = crypto::PublicKey;

#[derive(Deserialize, Debug)]
#[serde(from = "Uint256")]
pub struct U256(ethers::types::U256);

impl From<Uint256> for U256 {
    fn from(value: Uint256) -> Self {
        Self(ethers::types::U256::from_big_endian(
            value.to_be_bytes().as_slice(),
        ))
    }
}

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
