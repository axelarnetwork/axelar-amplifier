use connection_router::state::{CrossChainId, NewMessage};
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
    pub router_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages(Vec<NewMessage>),

    // Permissionless
    RouteMessages(Vec<NewMessage>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<NewMessage>)]
    GetMessages { message_ids: Vec<CrossChainId> },
}
