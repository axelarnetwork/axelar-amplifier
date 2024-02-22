use connection_router_api::{CrossChainId, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    VerifyMessages(Vec<Message>),

    // Permissionless
    /// Forward the given messages to the next step of the routing layer. If these messages are coming in from an external chain,
    /// they have to be verified first.
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Message>)]
    GetMessages { message_ids: Vec<CrossChainId> },
}
