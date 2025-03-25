use cosmwasm_schema::cw_serde;
// these messages and structs are extracted into a separate package to avoid circular dependencies
pub use service_registry_api::msg::{ExecuteMsg, QueryMsg, UpdatedServiceParams, VerifierDetails};

pub use crate::contract::MigrateMsg;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}
