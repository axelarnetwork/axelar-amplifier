use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

use crate::types::{Data, Proof};

#[cw_serde]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    ConstructProof { message_ids: Vec<String> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { proof_id: String },
}

#[cw_serde]
pub enum ProofStatus {
    Pending,
    Completed { execute_data: HexBinary }, // encoded data and proof sent to destination gateway
}

#[cw_serde]
pub struct GetProofResponse {
    pub proof_id: HexBinary,
    pub message_ids: Vec<String>,
    pub data: Data,
    pub proof: Proof,
    pub status: ProofStatus,
}
