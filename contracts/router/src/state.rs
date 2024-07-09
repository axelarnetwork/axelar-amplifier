use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};
use error_stack::{report, ResultExt};
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName};

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> error_stack::Result<(), Error> {
    CONFIG
        .save(storage, config)
        .change_context(Error::StoreFailure)
}

pub fn load_config(storage: &dyn Storage) -> error_stack::Result<Config, Error> {
    CONFIG.load(storage).change_context(Error::StoreFailure)
}

pub fn load_chain_by_chain_name(
    storage: &dyn Storage,
    chain_name: &ChainName,
) -> error_stack::Result<Option<ChainEndpoint>, Error> {
    chain_endpoints()
        .may_load(storage, chain_name.clone())
        .change_context(Error::StoreFailure)
}
pub fn load_chain_by_gateway(
    storage: &dyn Storage,
    gateway: &Addr,
) -> error_stack::Result<ChainEndpoint, Error> {
    chain_endpoints()
        .idx
        .gateway
        .load_chain_by_gateway(storage, gateway)
        .change_context(Error::StoreFailure)?
        .ok_or(report!(Error::GatewayNotRegistered))
}

#[cw_serde]
pub struct Config {
    pub nexus_gateway: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub struct ChainEndpointIndexes<'a> {
    pub gateway: GatewayIndex<'a>,
}

pub struct GatewayIndex<'a>(MultiIndex<'a, Addr, ChainEndpoint, ChainName>);

impl<'a> GatewayIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &ChainEndpoint) -> Addr,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        GatewayIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn load_chain_by_gateway(
        &self,
        storage: &dyn Storage,
        contract_address: &Addr,
    ) -> StdResult<Option<ChainEndpoint>> {
        match self
            .0
            .prefix(contract_address.clone())
            .range(storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, chain)] => Ok(Some(chain.to_owned())),
            _ => panic!("More than one gateway for chain"),
        }
    }
}

const CHAINS_PKEY: &str = "chains";

pub fn chain_endpoints<'a>() -> IndexedMap<'a, ChainName, ChainEndpoint, ChainEndpointIndexes<'a>> {
    return IndexedMap::new(
        CHAINS_PKEY,
        ChainEndpointIndexes {
            gateway: GatewayIndex::new(
                |_pk: &[u8], d: &ChainEndpoint| d.gateway.address.clone(),
                CHAINS_PKEY,
                "gateways",
            ),
        },
    );
}

impl<'a> IndexList<ChainEndpoint> for ChainEndpointIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<ChainEndpoint>> + '_> {
        let v: Vec<&dyn Index<ChainEndpoint>> = vec![&self.gateway.0];
        Box::new(v.into_iter())
    }
}
