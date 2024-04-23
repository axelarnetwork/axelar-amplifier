use axelar_wasm_std::VerificationStatus;
use cosmwasm_schema::{cw_serde, QueryResponses};
use router_api::Message;

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
    #[returns(Vec<(router_api::CrossChainId, VerificationStatus)>)]
    GetMessagesStatus { messages: Vec<Message> },
}
