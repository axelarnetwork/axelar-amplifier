use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};

use crate::ContractError;

pub const ID_SEPARATOR: char = ':';
#[cw_serde]
pub struct MessageID {
    value: String,
}

impl FromStr for MessageID {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(ID_SEPARATOR) || s.is_empty() {
            return Err(ContractError::InvalidMessageID {});
        }
        Ok(MessageID {
            value: s.to_lowercase(),
        })
    }
}

impl From<MessageID> for String {
    fn from(d: MessageID) -> Self {
        d.value
    }
}

impl ToString for MessageID {
    fn to_string(&self) -> String {
        self.value.clone()
    }
}

impl<'a> MessageID {
    pub fn as_str(&'a self) -> &'a str {
        self.value.as_str()
    }
}

#[cw_serde]
pub struct DomainName {
    value: String,
}

impl FromStr for DomainName {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(ID_SEPARATOR) || s.is_empty() {
            return Err(ContractError::InvalidDomainName {});
        }
        Ok(DomainName {
            value: s.to_lowercase(),
        })
    }
}

impl From<DomainName> for String {
    fn from(d: DomainName) -> Self {
        d.value
    }
}

impl ToString for DomainName {
    fn to_string(&self) -> String {
        self.value.clone()
    }
}

impl<'a> PrimaryKey<'a> for DomainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.value.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for DomainName {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.value.as_bytes())]
    }
}

impl KeyDeserialize for DomainName {
    type Output = String;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value).map_err(StdError::invalid_utf8)
    }
}

#[cw_serde]
pub struct Gateway {
    pub address: Addr,
    pub is_frozen: bool,
}

#[cw_serde]
pub struct Domain {
    pub name: DomainName,
    pub incoming_gateway: Gateway,
    pub outgoing_gateway: Gateway,
    pub is_frozen: bool,
}
