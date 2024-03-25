use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}
pub const CONFIG: Item<Config> = Item::new("config");
