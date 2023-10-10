use connection_router_api::msg::Message;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages(Vec<Message>),

    // Permissionless
    RouteMessages(Vec<Message>),
}
