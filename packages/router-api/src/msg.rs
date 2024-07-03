use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::{cw_serde, QueryResponses};
use std::collections::HashMap;

use crate::primitives::*;

#[cw_serde]
pub enum ExecuteMsg {
    /*
     * Governance Methods
     * All the below messages should only be called by governance
     */
    /// Registers a new chain with the router
    RegisterChain {
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    },
    /// Changes the gateway address associated with a particular chain
    UpgradeGateway {
        chain: ChainName,
        contract_address: Address,
    },

    /*
     * Router Admin Methods
     * All the below messages should only be called by the router admin
     */
    /// Freezes the specified chains in the specified directions.
    FreezeChains {
        chains: HashMap<ChainName, GatewayDirection>,
    },

    /// Unfreezes the specified chains in the specified directions.
    UnfreezeChains {
        chains: HashMap<ChainName, GatewayDirection>,
    },

    /// Emergency command to stop all amplifier routing.
    DisableRouting,

    /// Resumes routing after an emergency shutdown.
    EnableRouting,
    /*
     * Gateway Messages
     * The below messages can only be called by registered gateways
     */
    /// Routes a message to all outgoing gateways registered to the destination domain.
    /// Called by an incoming gateway
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
    #[returns(bool)]
    IsEnabled,
}
