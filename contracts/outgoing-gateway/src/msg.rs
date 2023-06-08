use connection_router::msg::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub enum ExecuteMsg {
    // For each message id, returns the associated message.
    // Fetches messages from the router if not found in storage.
    CollectMessages { message_ids: Vec<String> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Message>)]
    GetMessages { message_ids: Vec<String> },
}
