use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    // Returns a proof id (to use for signing)
    ConstructProof { message_ids: Vec<String> },
    // Sign a previously constructed proof
    SignProof { proof_id: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // TODO: return a proper type
    #[returns(HexBinary)]
    GetProof { proof_id: String },
}
