use crate::state::MessageStatus;
use connection_router::msg::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
    pub router_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Stores the messages internally. Can only be called by the router
    SendMessages { messages: Vec<Message> },

    // Returns a vector of (String,MessageStatus) tuples for each passed in message, consisting of message ID and current status
    // Permissionless
    VerifyMessages { messages: Vec<Message> },

    // For each message, checks for verification and sends message to the router if fully verified.
    // Returns a vector of (String,MessageStatus) tuples for each passed in message, consisting of message ID and current status
    // Permissionless
    ExecuteMessages { messages: Vec<Message> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<(Message,MessageStatus)>)]
    GetMessages { message_ids: Vec<String> },
}
