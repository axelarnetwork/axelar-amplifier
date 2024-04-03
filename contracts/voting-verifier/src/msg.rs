use cosmwasm_schema::{cw_serde, QueryResponses};

use axelar_wasm_std::{
    nonempty,
    operators::Operators,
    voting::{PollId, PollState, Vote},
    MajorityThreshold, VerificationStatus,
};
use connection_router_api::{ChainName, CrossChainId, Message};

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: nonempty::String,

    // params to query service_registry
    pub service_registry_address: nonempty::String,
    pub service_name: nonempty::String,

    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: u64,
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Computes the results of a poll
    // For all verified messages, calls MessagesVerified on the verifier
    EndPoll {
        poll_id: PollId,
    },

    // Casts votes for specified poll
    Vote {
        poll_id: PollId,
        votes: Vec<Vote>,
    },

    // returns a vector of true/false values, indicating current verification status for each message
    // starts a poll for any not yet verified messages
    VerifyMessages {
        messages: Vec<Message>,
    },

    // Starts a poll to confirm a worker set update on the external evm gateway
    VerifyWorkerSet {
        message_id: nonempty::String,
        new_operators: Operators,
    },

    // Update the threshold used for new polls. Callable only by governance
    UpdateVotingThreshold {
        new_voting_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub struct Poll {
    poll_id: PollId,
    messages: Vec<Message>,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Poll)]
    GetPoll { poll_id: PollId },

    #[returns(Vec<(CrossChainId, VerificationStatus)>)]
    GetMessagesStatus { messages: Vec<Message> },

    #[returns(VerificationStatus)]
    GetWorkerSetStatus { new_operators: Operators },

    #[returns(MajorityThreshold)]
    GetCurrentThreshold,
}

#[cw_serde]
pub struct VerifyMessagesResponse {
    pub verification_statuses: Vec<(CrossChainId, VerificationStatus)>,
}

#[cw_serde]
pub struct EndPollResponse {
    pub poll_result: PollState,
}
