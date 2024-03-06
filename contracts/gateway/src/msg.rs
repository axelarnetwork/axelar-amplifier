use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    pub verifier_address: String,
    pub router_address: String,
}
