use axelar_wasm_std::VerificationStatus;
use connection_router::state::Message;
use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<(connection_router::state::CrossChainId, VerificationStatus)>)]
    GetMessagesStatus { messages: Vec<Message> },
}
