use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256};
use msgs_derive::Permissions;
use router_api::{Address, ChainName, FIELD_DELIMITER};
use sha3::{Digest, Keccak256};

pub use crate::contract::MigrateMsg;

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
    /// Threshold of weighted votes required for voting to be considered complete for a particular message
    pub voting_threshold: MajorityThreshold,
    /// The number of blocks after which a poll expires
    pub block_expiry: nonempty::Uint64,
    /// The number of blocks to wait for on the source chain before considering a transaction final
    pub confirmation_height: u64,
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
    // transaction hash where the event was emitted
    pub transaction_hash: String,
}

#[cw_serde]
pub struct TransactionDetails {
    pub calldata: HexBinary,
    pub from: Address,
    pub to: Address,
    pub value: Uint256,
}

#[cw_serde]
pub struct Event {
    pub contract_address: Address, // address of contract emitting the event
    pub event_index: u64,          // index of the event in the transaction
    pub topics: Vec<HexBinary>,    // 1-4 topics
    pub data: HexBinary,           // arbitrary length hex data
}

#[cw_serde]
pub enum EventData {
    Evm {
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
}

#[cw_serde]
pub struct EventStatus {
    pub event: EventToVerify,
    pub status: VerificationStatus,
}

impl EventStatus {
    pub fn new(event: EventToVerify, status: VerificationStatus) -> Self {
        Self { event, status }
    }
}

impl TransactionDetails {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.calldata.as_slice());
        hasher.update(delimiter_bytes);
        hasher.update(self.from.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.to.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.value.to_string().as_bytes());
        hasher.update(delimiter_bytes);

        hasher.finalize().into()
    }
}

impl Event {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.contract_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(&self.event_index.to_le_bytes());
        hasher.update(delimiter_bytes);
        
        // Hash each topic
        for topic in &self.topics {
            hasher.update(topic.as_slice());
            hasher.update(delimiter_bytes);
        }
        
        hasher.update(self.data.as_slice());
        hasher.update(delimiter_bytes);

        hasher.finalize().into()
    }
}

impl EventData {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        match self {
            EventData::Evm { transaction_details, events } => {
                // Hash variant identifier
                hasher.update(b"Evm");
                hasher.update(delimiter_bytes);
                
                // Hash transaction details if present
                match transaction_details {
                    Some(tx_details) => {
                        hasher.update(b"some");
                        hasher.update(delimiter_bytes);
                        let tx_hash = tx_details.hash();
                        hasher.update(tx_hash.as_ref());
                        hasher.update(delimiter_bytes);
                    }
                    None => {
                        hasher.update(b"none");
                        hasher.update(delimiter_bytes);
                    }
                }
                
                // Hash each event
                for event in events {
                    let event_hash = event.hash();
                    hasher.update(event_hash.as_ref());
                    hasher.update(delimiter_bytes);
                }
            }
        }

        hasher.finalize().into()
    }
}

impl EventToVerify {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.event_id.source_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(&self.event_id.transaction_hash);
        hasher.update(delimiter_bytes);

        // Hash the event data using its hash function
        let event_data_hash = self.event_data.hash();
        hasher.update(event_data_hash.as_ref());

        hasher.finalize().into()
    }
}
