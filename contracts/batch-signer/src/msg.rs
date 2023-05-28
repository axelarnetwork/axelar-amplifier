use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

use crate::{
    command::SigningStatus,
    types::{KeccackHash, Proof},
};

#[cw_serde]
pub struct InstantiateMsg {
    pub gateway_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    // Returns a proof id (to use for signing)
    ConstructProof {
        message_ids: Vec<String>,
    },
    // Sign a previously constructed proof
    SignProof {
        proof_id: String,
        signature: HexBinary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { proof_id: String },
}

#[cw_serde]
pub struct GetProofResponse {
    pub proof_id: String,
    pub commands_ids: Vec<KeccackHash>,
    pub key_id: String,
    pub status: SigningStatus,
    pub data_encoded: HexBinary,
    pub proof: Proof,
    pub execute_data_encoded: HexBinary,
}
