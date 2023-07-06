use std::{
    ops::{BitAnd, BitOr, Not},
    str::FromStr,
};

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
        if !s.contains(ID_SEPARATOR) || s.is_empty() {
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
pub struct ChainName {
    value: String,
}

impl FromStr for ChainName {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(ID_SEPARATOR) || s.is_empty() {
            return Err(ContractError::InvalidChainName {});
        }
        Ok(ChainName {
            value: s.to_lowercase(),
        })
    }
}

impl From<ChainName> for String {
    fn from(d: ChainName) -> Self {
        d.value
    }
}

impl ToString for ChainName {
    fn to_string(&self) -> String {
        self.value.clone()
    }
}

impl<'a> PrimaryKey<'a> for ChainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.value.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for ChainName {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.value.as_bytes())]
    }
}

impl KeyDeserialize for ChainName {
    type Output = String;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value).map_err(StdError::invalid_utf8)
    }
}

#[cw_serde]
pub struct Gateway {
    pub address: Addr,
}

#[cw_serde]
pub struct ChainEndpoint {
    pub name: ChainName,
    pub gateway: Gateway,
    pub frozen_status: GatewayDirection,
}

#[cw_serde]
pub enum GatewayDirection {
    None = 0x00,
    Incoming = 0x01,
    Outgoing = 0x10,
    Bidirectional = 0x11,
}

impl TryFrom<u32> for GatewayDirection {
    type Error = ();
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == GatewayDirection::Bidirectional as u32 => Ok(GatewayDirection::Bidirectional),
            x if x == GatewayDirection::Incoming as u32 => Ok(GatewayDirection::Incoming),
            x if x == GatewayDirection::Outgoing as u32 => Ok(GatewayDirection::Outgoing),
            x if x == GatewayDirection::None as u32 => Ok(GatewayDirection::None),
            _ => Err(()),
        }
    }
}

impl BitOr for GatewayDirection {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        (self as u32 | rhs as u32)
            .try_into()
            .expect("unexpected GatewayDirection bitor result")
    }
}

impl Not for GatewayDirection {
    type Output = Self;
    fn not(self) -> Self::Output {
        // only want to invert the bottom two bits
        (!(self as u32) & 0x11)
            .try_into()
            .expect("unexpected GatewayDirection not result")
    }
}

impl BitAnd for GatewayDirection {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        (self as u32 & rhs as u32)
            .try_into()
            .expect("unexpected GatewayDirection bitand result")
    }
}
