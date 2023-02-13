use cosmwasm_std::Addr;
use cw_storage_plus::Map;

pub const ROUTES: Map<u128, Addr> = Map::new("routes");
