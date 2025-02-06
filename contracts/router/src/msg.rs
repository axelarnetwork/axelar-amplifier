use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    // admin controls freezing and unfreezing a chain
    pub admin_address: String,
    // governance votes on chains being added or upgraded
    pub governance_address: String,
    // the address of the axelarnet gateway
    pub axelarnet_gateway: String,
}

// these messages are extracted into a separate package to avoid circular dependencies
pub use router_api::msg::{ExecuteMsg, QueryMsg};

pub use crate::contract::migrations::MigrateMsg;
