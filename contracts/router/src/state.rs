use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};
use error_stack::ResultExt;
use mockall::automock;
use router_api::error::Error;
use router_api::{ChainEndpoint, ChainName};

#[automock]
pub trait Store {
    fn save_config(&mut self, config: Config) -> error_stack::Result<(), Error>;
    fn load_config(&self) -> error_stack::Result<Config, Error>;
    fn load_chain_by_gateway(
        &self,
        gateway: &Addr,
    ) -> error_stack::Result<Option<ChainEndpoint>, Error>;
    fn load_chain_by_chain_name(
        &self,
        chain_name: &ChainName,
    ) -> error_stack::Result<Option<ChainEndpoint>, Error>;
}

pub struct RouterStore<'a> {
    storage: &'a mut dyn Storage,
}

impl Store for RouterStore<'_> {
    fn save_config(&mut self, config: Config) -> error_stack::Result<(), Error> {
        CONFIG
            .save(self.storage, &config)
            .change_context(Error::StoreFailure)
    }

    fn load_config(&self) -> error_stack::Result<Config, Error> {
        CONFIG
            .load(self.storage)
            .change_context(Error::StoreFailure)
    }

    fn load_chain_by_gateway(
        &self,
        gateway: &Addr,
    ) -> error_stack::Result<Option<ChainEndpoint>, Error> {
        chain_endpoints()
            .idx
            .gateway
            .load_chain_by_gateway(self.storage, gateway)
            .change_context(Error::StoreFailure)
    }

    fn load_chain_by_chain_name(
        &self,
        chain_name: &ChainName,
    ) -> error_stack::Result<Option<ChainEndpoint>, Error> {
        chain_endpoints()
            .may_load(self.storage, chain_name.clone())
            .change_context(Error::StoreFailure)
    }
}

impl<'a> RouterStore<'a> {
    pub fn new(storage: &'a mut dyn Storage) -> Self {
        Self { storage }
    }
}

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub governance: Addr,
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

    #[deprecated(note = "use load_chain_by_gateway instead")]
    pub fn find_chain(
        &self,
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<ChainEndpoint>> {
        self.load_chain_by_gateway(deps.storage, contract_address)
    }

    fn load_chain_by_gateway(
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
