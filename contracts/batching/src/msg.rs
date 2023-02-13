use cosmwasm_schema::cw_serde;
use cosmwasm_std::CosmosMsg;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    Batch(BatchMsg),
}

#[cw_serde]
pub struct BatchMsg {
    pub must_succeed_msgs: Vec<CosmosMsg>,
    pub can_fail_msgs: Vec<CosmosMsg>,
}
