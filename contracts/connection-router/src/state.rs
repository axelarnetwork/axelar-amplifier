use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, StdError, StdResult};
use cw_storage_plus::{
    Index, IndexList, IndexedMap, Item, Key, KeyDeserialize, Map, MultiIndex, Prefixer, PrimaryKey,
};

use crate::ContractError;

#[cw_serde]
pub struct Message {
    pub id: String, // unique per source domain
    pub destination_address: String,
    pub destination_domain: DomainName,
    pub source_domain: DomainName,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl Message {
    pub fn uuid(&self) -> String {
        format!("{}-{}", self.source_domain.to_string(), self.id)
    }
}

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

#[cw_serde]
pub struct Gateway {
    pub address: Addr,
    pub is_frozen: bool,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
pub struct DomainName {
    value: String,
}

impl FromStr for DomainName {
    type Err = ContractError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
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
pub struct Domain {
    pub incoming_gateway: Gateway,
    pub outgoing_gateway: Gateway,
    pub is_frozen: bool,
}

pub struct DomainIndexes<'a> {
    pub incoming_gateway: MultiIndex<'a, Addr, Domain, DomainName>,
    pub outgoing_gateway: MultiIndex<'a, Addr, Domain, DomainName>,
}

const DOMAINS_PKEY: &str = "domains";

pub fn domains<'a>() -> IndexedMap<'a, DomainName, Domain, DomainIndexes<'a>> {
    return IndexedMap::new(
        DOMAINS_PKEY,
        DomainIndexes {
            incoming_gateway: MultiIndex::new(
                |_pk: &[u8], d: &Domain| d.incoming_gateway.address.clone(),
                DOMAINS_PKEY,
                "incoming_gateways",
            ),
            outgoing_gateway: MultiIndex::new(
                |_pk: &[u8], d: &Domain| d.outgoing_gateway.address.clone(),
                DOMAINS_PKEY,
                "outgoing_gateways",
            ),
        },
    );
}

impl<'a> IndexList<Domain> for DomainIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Domain>> + '_> {
        let v: Vec<&dyn Index<Domain>> = vec![&self.incoming_gateway, &self.outgoing_gateway];
        Box::new(v.into_iter())
    }
}

// a set of all message uuids
pub const MESSAGES: Map<String, ()> = Map::new("messages");
