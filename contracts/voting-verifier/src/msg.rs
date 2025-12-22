use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::Permissions;
use multisig::verifier_set::VerifierSet;
use router_api::Message;
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

    // Starts a poll to confirm a verifier set update on the external gateway
    #[permission(Any)]
    VerifyVerifierSet {
        message_id: nonempty::String,
        new_verifier_set: VerifierSet,
    },

    /// Update voting parameters. Callable only by governance.
    /// Each parameter is optional - `None` values keep the current configuration unchanged.
    /// This allows updating parameters individually or in combination.
    /// Updates only apply to future polls, not currently active ones.
    #[permission(Governance)]
    UpdateVotingParameters {
        /// Minimum fraction of total verifier weight required to reach consensus on a poll.
        /// `None` keeps current threshold.
        voting_threshold: Option<MajorityThreshold>,
        /// Number of blocks after which a poll expires if consensus is not reached.
        /// `None` keeps current block expiry.
        block_expiry: Option<nonempty::Uint64>,
        /// Minimum block depth required on the source chain for message verification
        /// when not using a finality flag to determine confirmation.
        /// `None` keeps current confirmation height.
        confirmation_height: Option<u64>,
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

    #[returns(VotingParameters)]
    VotingParameters,

    #[returns(crate::state::Poll)]
    PollByMessage { message: Message },
}

#[cw_serde]
pub struct VotingParameters {
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64,
    pub confirmation_height: u64,
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
