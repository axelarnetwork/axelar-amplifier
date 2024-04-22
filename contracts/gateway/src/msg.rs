use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    /// Address of the verifier contract on axelar associated with the source chain. E.g., the voting verifier contract.
    pub verifier_address: String,
    /// Address of the router contract on axelar.
    pub router_address: String,
}
