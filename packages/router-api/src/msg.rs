use std::collections::HashMap;

use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;

use crate::primitives::*;

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Registers a new chain with the router
    #[permission(Governance)]
    RegisterChain {
        chain: NormalizedChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    },
    /// Changes the gateway address associated with a particular chain
    #[permission(Governance)]
    UpgradeGateway {
        chain: NormalizedChainName,
        contract_address: Address,
    },
    /// Freezes the specified chains in the specified directions.
    #[permission(Elevated)]
    FreezeChains {
        chains: HashMap<NormalizedChainName, GatewayDirection>,
    },
    /// Unfreezes the specified chains in the specified directions.
    #[permission(Elevated)]
    UnfreezeChains {
        chains: HashMap<NormalizedChainName, GatewayDirection>,
    },

    /// Emergency command to stop all amplifier routing.
    #[permission(Elevated)]
    DisableRouting,

    /// Resumes routing after an emergency shutdown.
    #[permission(Elevated)]
    EnableRouting,

    /// Routes a message to all outgoing gateways registered to the destination domain.
    /// Called by an incoming gateway
    #[permission(Specific(gateway))]
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ChainEndpoint)]
    GetChainInfo(NormalizedChainName),

    // Returns a list of chains registered with the router
    // The list is paginated by:
    // - start_after: the chain name to start after, which the next page of results should start.
    // - limit: limit the number of chains returned, default is u32::MAX.
    #[returns(Vec<ChainEndpoint>)]
    Chains {
        start_after: Option<NormalizedChainName>,
        limit: Option<u32>,
    },
    #[returns(bool)]
    IsEnabled,
}
