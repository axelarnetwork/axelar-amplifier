use connection_router::msg::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub enum ExecuteMsg {
    // Stores the messages internally. Can only be called by the router
    SendMessages { messages: Vec<Message> },
    // Returns a vector of true/false values for each passed in message, indicating current verification status
    // Permissionless
    VerifyMessages { messages: Vec<Message> },

    // For each message, sends message to the router if fully verified
    // Permissionless
    ExecuteMessages { messages: Vec<Message> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Message>)]
    GetMessages { message_ids: Vec<String> },
}
