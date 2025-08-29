use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Coin;
use msgs_derive::Permissions;
use router_api::ChainName;

use crate::evm::{Event, TransactionDetails};

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
    /// Admin that can manage contract parameters
    pub admin_address: nonempty::String,
    /// Threshold of weighted votes required for voting to be considered complete for a particular message
    pub voting_threshold: MajorityThreshold,
    /// The number of blocks after which a poll expires
    pub block_expiry: nonempty::Uint64,
    /// Fee required to call verify_events
    pub fee: Coin,
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
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

    // Admin-only: update the required fee for verify_events
    #[permission(Admin)]
    UpdateFee { new_fee: Coin },

    // Admin-only: withdraw accumulated fee balance to a receiver
    #[permission(Admin)]
    Withdraw { receiver: nonempty::String },
}

#[cw_serde]
pub struct EventToVerify {
    pub source_chain: ChainName,
    pub event_data: String, // JSON string representing the serialized EventData
}



#[cw_serde]
pub enum EventData {
    Evm {
        transaction_hash: HexTxHash,
        transaction_details: Option<TransactionDetails>,
        events: Vec<Event>,
    },
    // Additional event variants for other blockchain types can be added here
}

#[cw_serde]
pub enum PollData {
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

    #[returns(Vec<EventStatus>)]
    EventsStatus(Vec<EventToVerify>),

    #[returns(MajorityThreshold)]
    CurrentThreshold,

    #[returns(Coin)]
    CurrentFee,
}

#[cw_serde]
pub struct EventStatus {
    pub event: EventToVerify,
    pub status: VerificationStatus,
}
