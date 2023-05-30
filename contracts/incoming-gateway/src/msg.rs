use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub destination_address: String,
    pub destination_domain: String,
    pub payload_hash: HexBinary,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    // Permissionless
    VerifyMessages { messages: Vec<Message> },

    // Callback for the verifier. Indicates each contained message was fully verified
    // Can only be called by the verifier
    MessagesVerified { messages: Vec<Message> },

    // For each message, sends message to the router if fully verified
    // Permissionless
    ExecuteMessages { messages: Vec<Message> },
}
