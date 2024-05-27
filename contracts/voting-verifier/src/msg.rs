use cosmwasm_schema::{cw_serde, QueryResponses};

use axelar_wasm_std::{
    msg_id::MessageIdFormat,
    nonempty,
    operators::Operators,
    voting::{PollId, Vote},
    MajorityThreshold, VerificationStatus,
};
use router_api::{ChainName, Message};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can call all messages of unrestricted governance permission level, like UpdateVotingThreshold.
    /// It can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet it should match the address of the Cosmos governance module.
    pub governance_address: nonempty::String,
    /// Service registry contract address on axelar.
    pub service_registry_address: nonempty::String,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: nonempty::String,
    /// Axelar's gateway contract address on the source chain
    pub source_gateway_address: nonempty::String,
    /// Threshold of weighted votes required for voting to be considered complete for a particular message
    pub voting_threshold: MajorityThreshold,
    /// The number of blocks after which a poll expires
    pub block_expiry: u64,
    /// The number of blocks to wait for on the source chain before considering a transaction final
    pub confirmation_height: u64,
    /// Name of the source chain
    pub source_chain: ChainName,
    /// Rewards contract address on axelar.
    pub rewards_address: String,
    /// Format that incoming messages should use for the id field of CrossChainId
    pub msg_id_format: MessageIdFormat,
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

    // Starts a poll to confirm a verifier set update on the external gateway
    VerifyVerifierSet {
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

    #[returns(Vec<MessageStatus>)]
    GetMessagesStatus { messages: Vec<Message> },

    #[returns(VerificationStatus)]
    GetVerifierSetStatus { new_operators: Operators },

    #[returns(MajorityThreshold)]
    GetCurrentThreshold,
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

#[cw_serde]
pub struct MigrateMsg {
    pub source_gateway_address: nonempty::String,
    pub msg_id_format: MessageIdFormat,
}
