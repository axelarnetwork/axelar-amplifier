use connection_router::state::{CrossChainId, Message};
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
    pub router_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages(Vec<Message>),

    // Permissionless
    RouteMessages(Vec<Message>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Message>)]
    GetMessages { message_ids: Vec<CrossChainId> },
}
