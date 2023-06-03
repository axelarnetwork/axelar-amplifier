use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

// TODO should be some type used across contracts?
#[cw_serde]
pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_domain: String,
    pub destination_address: String,
    pub payload_hash: HexBinary,
}

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
