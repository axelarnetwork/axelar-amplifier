use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use multisig::VerifierSet;
use router_api::Message;
pub use voting_verifier_api::msg::InstantiateMsg;

pub use crate::contract::MigrateMsg;

#[cw_serde]
#[derive(EnsurePermissions)]
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

    // Starts a poll to confirm a verifier set update on the external gateway
    #[permission(Any)]
    VerifyVerifierSet {
        message_id: nonempty::String,
        new_verifier_set: VerifierSet,
    },

    // Update the threshold used for new polls. Callable only by governance
    #[permission(Governance)]
    UpdateVotingThreshold {
        new_voting_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub enum PollData {
    Messages(Vec<Message>),
    VerifierSet(VerifierSet),
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

    #[returns(VerificationStatus)]
    VerifierSetStatus(VerifierSet),

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
