use connection_router::msg::Message;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of (String,bool) tuples for each passed in message, consisting of message ID and current verification status
    // Permissionless
    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
pub enum QueryMsg {
    IsVerified { messages: Vec<Message> },
}
