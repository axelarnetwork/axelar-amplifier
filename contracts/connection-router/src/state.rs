use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

#[cw_serde]
pub struct Message {
    pub id: String, // unique per source domain
    pub destination_address: String,
    pub destination_domain: String,
    pub source_domain: String,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl Message {
    // id field is unique per source domain. To make this universally unique, we prepend the source domain
    pub fn uuid(&self) -> String {
        let mut global_id = self.source_domain.clone();
        global_id.push('-');
        global_id.push_str(&self.id);
        global_id
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
pub struct Domain {
    pub incoming_gateway: Gateway,
    pub outgoing_gateway: Gateway,
    pub is_frozen: bool,
}

pub struct DomainIndexes<'a> {
    pub incoming_gateway: MultiIndex<'a, Addr, Domain, String>,
    pub outgoing_gateway: MultiIndex<'a, Addr, Domain, String>,
}

pub fn domains<'a>() -> IndexedMap<'a, &'a str, Domain, DomainIndexes<'a>> {
    return IndexedMap::new(
        "domains",
        DomainIndexes {
            incoming_gateway: MultiIndex::new(
                |_pk: &[u8], d: &Domain| d.incoming_gateway.address.clone(),
                "domains",
                "incoming_gateways",
            ),
            outgoing_gateway: MultiIndex::new(
                |_pk: &[u8], d: &Domain| d.outgoing_gateway.address.clone(),
                "domains",
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

// maps a message uuid ([source_domain]+[id]) to a sha256 hash of the contents
pub const MESSAGES: Map<String, String> = Map::new("messages");
