use cosmwasm_schema::cw_serde;
use incoming_gateway::msg::Message;

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    VerifyMessages { messages: Vec<Message> },
}
