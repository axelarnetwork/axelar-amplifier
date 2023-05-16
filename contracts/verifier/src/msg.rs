use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub enum ExecuteMsg {
    // Verifies a message corresponding to message_id. Returns true or false
    VerifyMessage { message_id: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // Verifies a message corresponding to message_id
    #[returns(bool)]
    VerifyMessage { message_id: String },
}
