use connection_router::state::Message;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
pub enum QueryMsg {
    IsVerified { messages: Vec<Message> },
}
