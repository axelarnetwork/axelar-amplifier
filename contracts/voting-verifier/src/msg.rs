use cosmwasm_schema::cw_serde;
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
pub struct InstantiateMsg {
    service_registry_address: String, // service registry to determine current worker stake
    verifier_address: String,         // verifier to call back to when messages are verified
    voting_generic_address: String,   // generic voting contract to use for polls
}

#[cw_serde]
pub enum ExecuteMsg {
    // Queries the service registry for current workers and their stakes.
    // Calls StartPoll on the generic voting contract
    // returns the poll id to be used for voting
    StartPoll { messages: Vec<Message> },

    // Calls EndPoll on the generic voting contract.
    // For all verified messages, calls MessagesVerified on the verifier
    EndPoll { poll_id: String },

    // returns a vector of true/false values, indicating current verification status for each message
    // calls StartPoll for any not yet verified messages
    VerifyMessages { messages: Vec<Message> },
}
