use std::fmt;
use std::hash::{Hash as StdHash, Hasher};

use cosmrs::{crypto, AccountId};
use ethers_core::types::{Address, H256};
use serde::{Deserialize, Serialize};

pub type EVMAddress = Address;
pub type Hash = H256;
pub type PublicKey = crypto::PublicKey;

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

#[cfg(test)]
pub mod test_utils {
    use ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use crate::types::{PublicKey, TMAddress};

    impl TMAddress {
        pub fn random(prefix: &str) -> Self {
            Self(
                PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
                    .account_id(prefix)
                    .expect("failed to convert to account identifier"),
            )
        }
    }
}
