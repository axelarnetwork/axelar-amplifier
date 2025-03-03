use axelar_core_std::nexus;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, CrossChainId, Message};

#[cw_serde]
pub enum ExecutableMessage {
    /// A message that has been sent by the router, but not executed yet.
    Approved(Message),
    /// An approved message that has been executed.
    Executed(Message),
}

#[cw_serde]
pub struct InstantiateMsg {
    /// The chain name for this gateway.
    pub chain_name: ChainName,
    /// Address of the router contract on axelar.
    pub router_address: String,
    /// Address of the nexus module account on axelar.
    pub nexus: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
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

    /// Initiate a cross-chain contract call from Axelarnet to another chain.
    /// If the destination chain is registered with core, the message will be routed to core with an optional token.
    /// Otherwise, the message will be routed to the destination chain's gateway via the router.
    #[permission(Any)]
    CallContract {
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    },

    /// Forward the given nexus messages to the next step of the routing layer.
    #[permission(Specific(nexus))]
    RouteMessagesFromNexus(Vec<nexus::execute::Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the sent messages for the given cross-chain ids.
    #[returns(Vec<Message>)]
    RoutableMessages { cc_ids: Vec<CrossChainId> },

    /// Returns the received messages with their status for the given cross-chain ids.
    #[returns(Vec<ExecutableMessage>)]
    ExecutableMessages { cc_ids: Vec<CrossChainId> },

    /// Returns the chain name for this gateway.
    #[returns(ChainName)]
    ChainName,
}
