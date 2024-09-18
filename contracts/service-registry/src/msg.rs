use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator_contract: Addr,
}

// these messages and structs are extracted into a separate package to avoid circular dependencies
pub use service_registry_api::msg::{ExecuteMsg, QueryMsg};
pub use service_registry_api::msg::{UpdatedServiceParams, VerifierDetails};
