use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Uint64;

#[cw_serde]
pub struct InstantiateMsg {
    pub service_name: String,
    pub threshold: Uint64,
}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
