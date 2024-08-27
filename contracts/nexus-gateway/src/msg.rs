use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName};

use crate::nexus;

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
    pub axelar_gateway: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Initiate a cross-chain contract call with token from Axelarnet to another chain.
    /// Note: This only works when the destination chain is a legacy chain.
    #[permission(Any)]
    CallContractWithToken {
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    },
    /// Route a cross-chain message from Axelarnet to another chain.
    /// Note: This only works when the destination chain is a legacy chain.
    #[permission(Specific(router))]
    RouteMessages(Vec<router_api::Message>),
    #[permission(Specific(nexus))]
    RouteMessagesFromNexus(Vec<nexus::Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
