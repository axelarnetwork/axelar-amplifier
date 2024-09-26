use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

// these messages and structs are extracted into a separate package to avoid circular dependencies
pub use service_registry_api::msg::{ExecuteMsg, QueryMsg, UpdatedServiceParams, VerifierDetails};
