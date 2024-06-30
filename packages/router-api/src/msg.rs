use crate::primitives::*;
use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    // Registers a new chain with the router
    #[permission(Governance)]
    RegisterChain {
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    },
    // Changes the gateway address associated with a particular chain
    #[permission(Governance)]
    UpgradeGateway {
        chain: ChainName,
        contract_address: Address,
    },
    // Freezes a chain, in the specified direction.
    #[permission(Admin)]
    FreezeChain {
        chain: ChainName,
        direction: GatewayDirection,
    },
    // Unfreezes a chain, in the specified direction.
    #[permission(Elevated)]
    UnfreezeChain {
        chain: ChainName,
        direction: GatewayDirection,
    },

    /*
     * Gateway Messages
     * The below messages can only be called by registered gateways
     */
    // Routes a message to all outgoing gateways registered to the destination domain.
    // Called by an incoming gateway
    #[permission(Specific(gateway))]
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ChainEndpoint)]
    GetChainInfo(ChainName),

    // Returns a list of chains registered with the router
    // The list is paginated by:
    // - start_after: the chain name to start after, which the next page of results should start.
    // - limit: limit the number of chains returned, default is u32::MAX.
    #[returns(Vec<ChainEndpoint>)]
    Chains {
        start_after: Option<ChainName>,
        limit: Option<u32>,
    },
}
