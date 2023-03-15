use auth_vote::AuthVoting;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256, Uint64};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct ServiceInfo {
    pub service_registry: Addr,
    pub name: String,
    pub reward_pool: Addr,
    pub router_contract: Addr,
}

#[cw_serde]
pub struct InboundSettings {
    pub source_chain_name: String, // TODO: rename to inbound?
    pub gateway_address: Addr,     // TODO: rename to inbound?
    pub confirmation_height: Uint64,
}

pub const ADMIN: Item<Addr> = Item::new("admin");
pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const INBOUND_SETTINGS: Item<InboundSettings> = Item::new("inbound_settings");
pub const AUTH_MODULE: Item<AuthVoting> = Item::new("auth_module");
pub const WORKERS_VOTING_POWER: Map<Addr, Uint256> = Map::new("workers_whitelist");
