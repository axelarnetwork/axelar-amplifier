use cosmwasm_schema::cw_serde;
use incoming_gateway::msg::Message;

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    VerifyMessages { messages: Vec<Message> },

    // Callback for 1 or more verification methods. Indicates each contained message was verified by the calling contract
    // If enough verifications are received to satisfy the security policy, passes the result to the gateway
    MessagesVerified { messages: Vec<Message> },
}
