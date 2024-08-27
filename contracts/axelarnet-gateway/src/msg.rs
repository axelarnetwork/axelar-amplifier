use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::state::MessageWithStatus;

#[cw_serde]
pub struct InstantiateMsg {
    /// The chain name for this gateway.
    pub chain_name: ChainName,
    /// Address of the router contract on axelar.
    pub router_address: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Initiate a cross-chain contract call from Axelarnet to another chain.
    /// The message will be routed to the destination chain's gateway via the router.
    #[permission(Any)]
    CallContract {
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    },

    /// Forward the given messages to the next step of the routing layer.
    /// Messages initiated via `CallContract` can be forwarded again to the router.
    /// If the messages are coming from the router, then they are marked ready for execution.
    #[permission(Any)]
    RouteMessages(Vec<Message>),

    /// Execute the message at the destination contract with the corresponding payload.
    /// The message is marked as executed and thus can't be executed again.
    #[permission(Any)]
    Execute {
        cc_id: CrossChainId,
        payload: HexBinary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the sent messages for the given cross-chain ids.
    #[returns(Vec<Message>)]
    SentMessages { cc_ids: Vec<CrossChainId> },

    /// Returns the received messages with their status for the given cross-chain ids.
    #[returns(Vec<MessageWithStatus>)]
    ReceivedMessages { cc_ids: Vec<CrossChainId> },

    /// Returns the chain name for this gateway.
    #[returns(ChainName)]
    ChainName,
}
