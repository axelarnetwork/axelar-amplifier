use cosmwasm_schema::{cw_serde, QueryResponses};
use connection_router::types::Message;


#[cw_serde]
pub enum ExecuteMsg {
    // Fetch pending messages from the router
    FetchPendingMessages { limit: Option<u32> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Message>)]
    GetMessages { message_ids: Vec<String> },
}
