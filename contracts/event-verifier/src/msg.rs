use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256};
use msgs_derive::Permissions;
use router_api::{Address, ChainName, Message, FIELD_DELIMITER};
use sha3::{Digest, Keccak256};
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

    // returns a vector of true/false values, indicating current verification status for each event
    // starts a poll for any not yet verified events
    #[permission(Any)]
    VerifyEvents(Vec<EventToVerify>),



    // Update the threshold used for new polls. Callable only by governance
    #[permission(Governance)]
    UpdateVotingThreshold {
        new_voting_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub struct EventToVerify {
    pub event_id: EventId,
    pub event_data: EventData,
}

#[cw_serde]
pub struct EventId {
    // chain that emitted the event in question
    pub source_chain: ChainName,
    // same message id type as used for GMP
    pub message_id: String,
    // address of contract emitting the event
    pub contract_address: Address

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
    Events(Vec<EventToVerify>),
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

impl EventToVerify {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.event_id.source_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(&self.event_id.message_id);
        hasher.update(delimiter_bytes);
        hasher.update(self.event_id.contract_address.as_str());
        hasher.update(delimiter_bytes);
        
        // Hash the event data
        let event_data_bytes = serde_json::to_vec(&self.event_data)
            .expect("failed to serialize event data");
        hasher.update(event_data_bytes);

        hasher.finalize().into()
    }
}
