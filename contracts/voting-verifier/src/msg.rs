use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct Message {
    id: String,
    source_address: String,
    destination_address: String,
    destination_domain: String,
    payload_hash: HexBinary,
}
#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    // returns a poll id to be used for voting
    StartPoll { messages: Vec<Message> },

    //
    EndPoll { poll_id: String },

    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
