use cosmwasm_schema::{cw_serde, QueryResponses};

use axelar_wasm_std::Threshold;
use connection_router::msg::Message;

#[cw_serde]
pub struct InstantiateMsg {
    // params to query register service
    pub service_registry_address: String,
    pub service_name: String,

    pub source_gateway_address: String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64,
    pub confirmation_height: u64,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Computes the results of a poll
    // For all verified messages, calls MessagesVerified on the verifier
    EndPoll { poll_id: String },

    // Casts votes for specified poll
    Vote { poll_id: String, votes: Vec<bool> },

    // returns a vector of true/false values, indicating current verification status for each message
    // starts a poll for any not yet verified messages
    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
pub struct Poll {
    poll_id: String,
    messages: Vec<Message>,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Poll)]
    GetPoll { poll_id: String },
}

#[cw_serde]
pub struct VerifyMessagesResponse {
    pub verification_statuses: Vec<(String, bool)>,
}
