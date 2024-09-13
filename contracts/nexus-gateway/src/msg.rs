use axelar_core_std::nexus;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;

#[cw_serde]
pub struct MigrateMsg {
    pub axelarnet_gateway: String,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
    pub axelarnet_gateway: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Initiate a cross-chain contract call with token from Axelarnet to another chain.
    /// Note: This only works when the destination chain is a legacy chain.
    #[permission(Specific(gateway))]
    RouteMessageWithToken(router_api::Message),
    /// Route a cross-chain message from Axelarnet to another chain.
    /// Note: This only works when the destination chain is a legacy chain.
    #[permission(Specific(router))]
    RouteMessages(Vec<router_api::Message>),
    #[permission(Specific(nexus))]
    RouteMessagesFromNexus(Vec<nexus::execute::Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
