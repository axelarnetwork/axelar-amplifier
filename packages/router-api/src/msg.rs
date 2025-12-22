use std::collections::HashMap;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::Permissions;

use crate::primitives::*;

// Pagination limits
const DEFAULT_PAGINATION_LIMIT: u32 = u32::MAX;

fn default_pagination_limit() -> nonempty::Uint32 {
    nonempty::Uint32::try_from(DEFAULT_PAGINATION_LIMIT)
        .expect("default pagination limit must be a u32")
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    /// Registers a new chain with the router
    #[permission(Governance, Proxy(coordinator))]
    RegisterChain {
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    },
    /// Changes the gateway address associated with a particular chain
    #[permission(Governance)]
    UpgradeGateway {
        chain: ChainName,
        contract_address: Address,
    },
    /// Freezes the specified chains in the specified directions.
    #[permission(Elevated)]
    FreezeChains {
        chains: HashMap<ChainName, GatewayDirection>,
    },
    /// Unfreezes the specified chains in the specified directions.
    #[permission(Elevated)]
    UnfreezeChains {
        chains: HashMap<ChainName, GatewayDirection>,
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

    /// Update admin address.
    #[permission(Elevated)]
    UpdateAdmin { new_admin_address: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ChainEndpoint)]
    ChainInfo(ChainName),

    // Returns a list of chains registered with the router
    // The list is paginated by:
    // - start_after: the chain name to start after, which the next page of results should start.
    // - limit: limit the number of chains returned, default is u32::MAX.
    #[returns(Vec<ChainEndpoint>)]
    Chains {
        start_after: Option<ChainName>,
        #[serde(default = "default_pagination_limit")]
        limit: nonempty::Uint32,
    },
    #[returns(bool)]
    IsEnabled,
}
