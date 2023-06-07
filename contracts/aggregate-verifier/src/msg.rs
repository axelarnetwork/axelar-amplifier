use connection_router::msg::Message;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    VerifyMessages { messages: Vec<Message> },
}
