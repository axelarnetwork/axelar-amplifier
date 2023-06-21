use connection_router::msg::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    service_registry_address: String, // service registry to determine current worker stake
    verifier_address: String,         // verifier to call back to when messages are verified
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
