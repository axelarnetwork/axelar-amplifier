use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use router_api::{Address, ChainName, CrossChainId, Message};

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    /// Initiate a cross-chain contract call from Axelarnet to another chain.
    /// The message will be routed to the destination chain's gateway via the router.
    CallContract {
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    },

    // Permissioned: Can only be called by the router
    /// Receive messages from the router and mark them as approved.
    RouteMessages(Vec<Message>),

    // Permissioned: Can be called by the address receiving the message
    /// Validate if the message was received for the caller contract and mark as executed. The receiving contract should call this before executing a message.
    ValidateMessage(Message),
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
