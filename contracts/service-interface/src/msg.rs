use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(UnbondAllowedResponse)]
    UnbondAllowed { worker_address: Addr },
}

#[cw_serde]
pub struct UnbondAllowedResponse {
    pub error: Option<String>,
}
