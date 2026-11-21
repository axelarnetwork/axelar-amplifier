use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::Permissions;
use router_api::ChainName;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{xrpl_account_id_string, XRPLAccountId};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: nonempty::String,
    /// Address that can call all messages of unrestricted governance permission level, like UpdateVotingParameters.
    /// It can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet it should match the address of the Cosmos governance module.
    pub governance_address: nonempty::String,
    /// Service registry contract address on axelar.
    pub service_registry_address: nonempty::String,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: nonempty::String,
    /// Axelar's gateway contract address on the source chain (i.e., the XRPL multisig address).
    /// This XRPL multisig account is controlled by Axelar verifiers, via transactions created on the XRPLMultisigProver.
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub source_gateway_address: XRPLAccountId,
    /// Threshold of weighted votes required for voting to be considered complete for a particular message
    pub voting_threshold: MajorityThreshold,
    /// The number of blocks after which a poll expires
    pub block_expiry: nonempty::Uint64,
    /// The number of blocks/ledgers to wait for on the source chain before considering a transaction final
    pub confirmation_height: u32,
    /// Name of the source chain
    pub source_chain: ChainName,
    /// Rewards contract address on axelar.
    pub rewards_address: nonempty::String,
}

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
    VerifyMessages(Vec<XRPLMessage>),

    /// Update voting parameters. Callable only by governance.
    /// Each parameter is optional - `None` values keep the current configuration unchanged.
    /// This allows updating parameters individually or in combination.
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
        confirmation_height: Option<u32>,
    },

    // Engages execution killswitch.
    #[permission(Elevated)]
    EnableExecution,

    // Disengages execution killswitch.
    #[permission(Elevated)]
    DisableExecution,

    // Updates the address of the admin.
    #[permission(Elevated)]
    UpdateAdmin { new_admin_address: String },
}

#[cw_serde]
pub enum PollData {
    Messages(Vec<XRPLMessage>),
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
    MessagesStatus(Vec<XRPLMessage>),

    #[returns(VotingParameters)]
    VotingParameters,
}

#[cw_serde]
pub struct VotingParameters {
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64,
    pub confirmation_height: u32,
}

#[cw_serde]
pub struct MessageStatus {
    pub message: XRPLMessage,
    pub status: VerificationStatus,
}

impl MessageStatus {
    pub fn new(message: XRPLMessage, status: VerificationStatus) -> Self {
        Self { message, status }
    }
}
