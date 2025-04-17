use cosmwasm_schema::cw_serde;
// these messages are extracted into a separate package to avoid circular dependencies
pub use gateway_api::msg::{ExecuteMsg, QueryMsg};

pub use crate::contract::MigrateMsg;

#[cw_serde]
pub struct InstantiateMsg {
    /// Address of the verifier contract on axelar associated with the source chain. E.g., the voting verifier contract.
    pub verifier_address: String,
    /// Address of the router contract on axelar.
    pub router_address: String,
}
