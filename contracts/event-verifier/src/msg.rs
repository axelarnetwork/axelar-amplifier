use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256};
use msgs_derive::Permissions;
use router_api::{Address, ChainName, Message};
pub use voting_verifier_api::msg::InstantiateMsg;

pub use crate::contract::MigrateMsg;

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    // Computes the results of a poll
    // For all verified messages, calls MessagesVerified on the verifier
    #[permission(Any)]
    EndPoll { poll_id: PollId },

    // Casts votes for specified poll
    #[permission(Any)]
    Vote { poll_id: PollId, votes: Vec<Vote> },

    // returns a vector of true/false values, indicating current verification status for each message
    // starts a poll for any not yet verified messages
    #[permission(Any)]
    VerifyMessages(Vec<Message>),



    // Update the threshold used for new polls. Callable only by governance
    #[permission(Governance)]
    UpdateVotingThreshold {
        new_voting_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub struct EventToVerify {
    event_id: EventId,
    event_data: EventData,
}

#[cw_serde]
pub struct EventId {
    // chain that emitted the event in question
    source_chain: ChainName,
    // same message id type as used for GMP
    message_id: String,
    // address of contract emitting the event
    contract_address: Address

}

#[cw_serde]
pub enum EventData {
    Evm {
        topics: Vec<Uint256>, // 1-4 topics
        data: HexBinary,      // arbitrary length hex data
    },
    // Additional event variants for other blockchain types can be added here
}

#[cw_serde]
pub enum PollData {
    Messages(Vec<Message>),
}
#[cw_serde]
pub struct PollResponse {
    pub poll: WeightedPoll,
    pub data: PollData,
    pub status: PollStatus,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(PollResponse)]
    Poll { poll_id: PollId },

    #[returns(Vec<MessageStatus>)]
    MessagesStatus(Vec<Message>),

    #[returns(MajorityThreshold)]
    CurrentThreshold,
}

#[cw_serde]
pub struct MessageStatus {
    pub message: Message,
    pub status: VerificationStatus,
}

impl MessageStatus {
    pub fn new(message: Message, status: VerificationStatus) -> Self {
        Self { message, status }
    }
}
