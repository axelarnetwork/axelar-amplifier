use connection_router::state::Message;
use cosmwasm_schema::cw_serde;

use crate::nexus;

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    RouteMessagesToNexus(Vec<Message>),
    RouteMessagesToRouter(Vec<nexus::Message>),
}
