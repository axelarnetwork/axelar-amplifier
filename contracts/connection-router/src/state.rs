use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdError, StdResult};
use cw_storage_plus::{
    Index, IndexList, IndexedMap, Item, Key, KeyDeserialize, Map, MultiIndex, Prefixer, PrimaryKey,
};

use crate::ContractError;

pub const ID_SEPARATOR: char = ':';
#[cw_serde]
pub struct MessageID {
    value: String,
}

impl FromStr for MessageID {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(ID_SEPARATOR) {
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
pub struct Message {
    id: MessageID, // unique per source domain
    pub destination_address: String,
    pub destination_domain: DomainName,
    pub source_domain: DomainName,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl Message {
    pub fn new(
        id: MessageID,
        destination_address: String,
        destination_domain: DomainName,
        source_domain: DomainName,
        source_address: String,
        payload_hash: HexBinary,
    ) -> Self {
        Message {
            id,
            destination_address,
            destination_domain: destination_domain,
            source_domain,
            source_address,
            payload_hash,
        }
    }

    pub fn id(&self) -> String {
        format!(
            "{}{}{}",
            self.source_domain.to_string(),
            ID_SEPARATOR,
            self.id.to_string()
        )
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
        if s.contains(ID_SEPARATOR) {
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
    pub name: DomainName,
    pub incoming_gateway: Gateway,
    pub outgoing_gateway: Gateway,
    pub is_frozen: bool,
}

pub struct DomainIndexes<'a> {
    pub incoming_gateway: GatewayIndex<'a>,
    pub outgoing_gateway: GatewayIndex<'a>,
}

pub struct GatewayIndex<'a>(MultiIndex<'a, Addr, Domain, DomainName>);

impl<'a> GatewayIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &Domain) -> Addr,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        GatewayIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn find_domain(
        &self,
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<Domain>> {
        let matching_domains = self
            .0
            .prefix(contract_address.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<(String, Domain)>, _>>()?;
        match &matching_domains[..] {
            [] => Ok(None),
            [(name, domain)] => Ok(Some(domain.clone())),
            _ => panic!("More than one gateway for domain"),
        }
    }
}

const DOMAINS_PKEY: &str = "domains";

pub fn domains<'a>() -> IndexedMap<'a, DomainName, Domain, DomainIndexes<'a>> {
    return IndexedMap::new(
        DOMAINS_PKEY,
        DomainIndexes {
            incoming_gateway: GatewayIndex::new(
                |_pk: &[u8], d: &Domain| d.incoming_gateway.address.clone(),
                DOMAINS_PKEY,
                "incoming_gateways",
            ),
            outgoing_gateway: GatewayIndex::new(
                |_pk: &[u8], d: &Domain| d.outgoing_gateway.address.clone(),
                DOMAINS_PKEY,
                "outgoing_gateways",
            ),
        },
    );
}

impl<'a> IndexList<Domain> for DomainIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Domain>> + '_> {
        let v: Vec<&dyn Index<Domain>> = vec![&self.incoming_gateway.0, &self.outgoing_gateway.0];
        Box::new(v.into_iter())
    }
}

// a set of all message uuids
pub const MESSAGES: Map<String, ()> = Map::new("messages");
