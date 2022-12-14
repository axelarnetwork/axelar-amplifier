use cosmwasm_std::CosmosMsg;

pub struct InstantiateMsg {}

pub enum ExecuteMsg {
    Batch(BatchMsg),
}

pub struct BatchMsg {
    pub must_succeed_msgs: Vec<CosmosMsg>,
    pub can_fail_msgs: Vec<CosmosMsg>,
}
