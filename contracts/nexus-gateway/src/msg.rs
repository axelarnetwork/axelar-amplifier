use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;

use crate::nexus;

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Specific(router))]
    RouteMessages(Vec<router_api::Message>),
    #[permission(Specific(nexus))]
    RouteMessagesFromNexus(Vec<nexus::Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
