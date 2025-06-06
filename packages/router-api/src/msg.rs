use std::collections::HashMap;

use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Response};
use msgs_derive::EnsurePermissions;
use msgs_external_execute::ExternalExecute;

use crate::error::Error;
use crate::primitives::*;

#[cw_serde]
#[derive(EnsurePermissions, ExternalExecute)]
pub enum ExecuteMsg {
    /// Registers a new chain with the router
    #[permit(coordinator)]
    #[permission(Governance)]
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

    #[permission(Specific(coordinator))]
    ExecuteFromCoordinator {
        original_sender: Addr,
        msg: Box<ExecuteMsg>,
    },
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
        limit: Option<u32>,
    },
    #[returns(bool)]
    IsEnabled,
}
