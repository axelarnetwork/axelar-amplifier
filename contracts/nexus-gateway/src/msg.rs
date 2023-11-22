use connection_router::state::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    VerifyMessages(Vec<Message>),
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
