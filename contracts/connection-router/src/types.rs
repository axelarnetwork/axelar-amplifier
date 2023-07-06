use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use flagset::{flags, FlagSet};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub frozen_status: GatewayDirectionFlagSet,
}

flags! {
    #[derive(Serialize,Deserialize, JsonSchema)]
pub enum GatewayDirection : u8 {
    None = 0b00,
    Incoming = 0b01,
    Outgoing = 0b10,
    Bidirectional = (GatewayDirection::Incoming | GatewayDirection::Outgoing).bits() ,
}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GatewayDirectionFlagSet(pub FlagSet<GatewayDirection>);

impl JsonSchema for GatewayDirectionFlagSet {
    fn schema_name() -> String {
        "GatewayDirectionFlagSet".to_string()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        GatewayDirection::json_schema(gen)
    }
}
