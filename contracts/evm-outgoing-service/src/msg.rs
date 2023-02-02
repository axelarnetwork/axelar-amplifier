use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};

#[cw_serde]
pub struct InstantiateMsg {
    pub router_contract: Addr,
    pub destination_chain_id: Uint256,
    pub destination_chain_name: String,
}

#[cw_serde]
pub enum ExecuteMsg {}
