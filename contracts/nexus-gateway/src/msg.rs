use connection_router::state::NewMessage;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    pub nexus: String,
    pub router: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    VerifyMessages(Vec<NewMessage>),
    RouteMessages(Vec<NewMessage>),
}
