use connection_router::types::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    // Permissionless
    VerifyMessages { messages: Vec<Message> },

    // For each message, sends message to the router if fully verified
    // Permissionless
    ExecuteMessages { messages: Vec<Message> },
}
