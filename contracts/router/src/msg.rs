use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    // admin controls freezing and unfreezing a chain
    pub admin_address: String,
    // governance votes on chains being added or upgraded
    pub governance_address: String,
    // the address of the nexus gateway
    pub nexus_gateway: String,
}
