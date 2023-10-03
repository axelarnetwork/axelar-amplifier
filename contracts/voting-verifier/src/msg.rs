use cosmwasm_schema::{cw_serde, QueryResponses};

use axelar_wasm_std::{
    nonempty,
    operators::Operators,
    voting::{PollID, PollResult},
    Threshold,
};
use connection_router::state::{ChainName, CrossChainId, Message, MessageId};

#[cw_serde]
pub struct InstantiateMsg {
    // params to query register service
    pub service_registry_address: nonempty::String,
    pub service_name: nonempty::String,

    pub source_gateway_address: nonempty::String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64,
    pub confirmation_height: u64,
    pub source_chain: ChainName,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Computes the results of a poll
    // For all verified messages, calls MessagesVerified on the verifier
    EndPoll {
        poll_id: PollID,
    },

    // Casts votes for specified poll
    Vote {
        poll_id: PollID,
        votes: Vec<bool>,
    },

    // returns a vector of true/false values, indicating current verification status for each message
    // starts a poll for any not yet verified messages
    VerifyMessages {
        messages: Vec<Message>,
    },

    // Starts a poll to confirm a worker set update on the external evm gateway
    ConfirmWorkerSet {
        message_id: MessageId,
        new_operators: Operators,
    },
}

#[cw_serde]
pub struct Poll {
    poll_id: PollID,
    messages: Vec<Message>,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Poll)]
    GetPoll { poll_id: PollID },

    #[returns(Vec<(CrossChainId, bool)>)]
    IsVerified { messages: Vec<Message> },

    #[returns(bool)]
    IsWorkerSetConfirmed { new_operators: Operators },
}

#[cw_serde]
pub struct VerifyMessagesResponse {
    pub verification_statuses: Vec<(CrossChainId, bool)>,
}

#[cw_serde]
pub struct EndPollResponse {
    pub poll_result: PollResult,
}
