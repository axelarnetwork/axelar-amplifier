use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

// TODO: should be some type used across contracts?
#[cw_serde]
pub struct Message {
    id: String,
    source_address: String,
    destination_address: String,
    destination_domain: String,
    payload_hash: HexBinary,
}

#[cw_serde]
pub enum ExecuteMsg {
    // returns true or false
    VerifyMessage { msg: Message },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    VerifyMessage { msg: Message },
}
