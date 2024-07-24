use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{CrossChainId, Message};

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<Message>),

    /// Forward the given messages to the next step of the routing layer. If these messages are coming in from an external chain,
    /// they have to be verified first.
    #[permission(Any)]
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),
}
