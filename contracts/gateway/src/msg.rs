use cosmwasm_schema::cw_serde;
// these messages are extracted into a separate package to avoid circular dependencies
pub use gateway_api::msg::{ExecuteMsg, QueryMsg, InstantiateMsg};

pub use crate::contract::MigrateMsg;

