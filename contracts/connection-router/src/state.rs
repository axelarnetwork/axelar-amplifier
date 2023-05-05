use core::panic;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use crate::types::{Domain, DomainName};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

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
        let mut matching_domains = self
            .0
            .prefix(contract_address.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?;

        if matching_domains.len() > 1 {
            panic!("More than one gateway for domain")
        }

        Ok(matching_domains.pop().map(|(_, domain)| domain))
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

const MESSAGE_QUEUE_SUFFIX: &str = "-messages";
pub fn get_message_queue_id(destination_domain: &DomainName) -> String {
    format!("{}{}", destination_domain.to_string(), MESSAGE_QUEUE_SUFFIX)
}
