// these messages are extracted into a separate package to avoid circular dependencies
pub use gateway_api::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

pub use crate::contract::MigrateMsg;
