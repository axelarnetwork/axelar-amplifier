use std::fmt;
use std::hash::{Hash as StdHash, Hasher};
use std::str::FromStr;

use cosmrs::AccountId;
use deref_derive::Deref;
use error_stack::{ensure, Report};
use ethers_core::types::{Address, H256};
use report::ResultCompatExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PREFIX;

pub mod debug;
mod key;
pub(crate) mod starknet;
#[cfg(test)]
pub use key::test_utils::random_cosmos_public_key;
pub use key::{CosmosPublicKey, PublicKey};

pub type EVMAddress = Address;
pub type Hash = H256;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid Axelar address {0}")]
    InvalidAxelarAddress(String),

    #[error("invalid prefix for Axelar address {0}")]
    InvalidAxelarAddressPrefix(String),
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref)]
pub struct AxelarAddress(TMAddress);

impl TryFrom<TMAddress> for AxelarAddress {
    type Error = Report<Error>;

    fn try_from(value: TMAddress) -> error_stack::Result<AxelarAddress, Error> {
        ensure!(
            value.prefix() == PREFIX,
            Error::InvalidAxelarAddressPrefix(value.to_string())
        );

        Ok(Self(value))
    }
}

impl From<AxelarAddress> for TMAddress {
    fn from(value: AxelarAddress) -> Self {
        value.0
    }
}

impl FromStr for AxelarAddress {
    type Err = Report<Error>;

    fn from_str(s: &str) -> error_stack::Result<AxelarAddress, Error> {
        let value =
            TMAddress::from_str(s).change_context(Error::InvalidAxelarAddress(s.to_string()))?;
        value.try_into()
    }
}

impl TryFrom<AccountId> for AxelarAddress {
    type Error = Report<Error>;

    fn try_from(account_id: AccountId) -> error_stack::Result<AxelarAddress, Error> {
        let value = TMAddress::from(account_id);
        value.try_into()
    }
}

impl AsRef<TMAddress> for AxelarAddress {
    fn as_ref(&self) -> &TMAddress {
        &self.0
    }
}

impl fmt::Display for AxelarAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::key::test_utils::random_cosmos_public_key;
    use crate::types::{AxelarAddress, TMAddress};
    use crate::PREFIX;

    impl TMAddress {
        pub fn random(prefix: &str) -> Self {
            Self(
                random_cosmos_public_key()
                    .account_id(prefix)
                    .expect("failed to convert to account identifier"),
            )
        }
    }

    impl AxelarAddress {
        pub fn random() -> Self {
            Self(TMAddress::random(PREFIX))
        }
    }
}
