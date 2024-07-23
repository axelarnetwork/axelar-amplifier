use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, CrossChainId, Message};

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

    /// Receive messages from the router and mark them as approved.
    #[permission(Specific(router))]
    RouteMessages(Vec<Message>),

    /// Execute a cross-chain message destined for Axelar with the corresponding payload.
    #[permission(Any)]
    ExecuteMessage {
        message: Message,
        payload: HexBinary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    GetOutgoingMessages { message_ids: Vec<CrossChainId> },

    // check if message is approved
    #[returns(bool)]
    IsMessageApproved { message: Message },

    // check if message is executed
    #[returns(bool)]
    IsMessageExecuted { message_id: CrossChainId },
}
