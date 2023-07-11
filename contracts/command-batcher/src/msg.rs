use std::collections::HashMap;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint256, Uint64};

use crate::types::{Data, Proof};

#[cw_serde]
pub struct InstantiateMsg {
    pub gateway_address: String,
    pub multisig_address: String,
    pub registry_address: String,
    pub destination_chain_id: Uint256,
    pub service_name: String,
    pub pub_keys: HashMap<String, HexBinary>, // TODO: this will be moved once keygen and key rotation are introduced
    pub quorum_threshold: (Uint64, Uint64),
}

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
pub struct GetProofResponse {
    pub proof_id: HexBinary,
    pub message_ids: Vec<String>,
    pub data: Data,
    pub proof: Proof,
    pub execute_data: HexBinary, // encoded data and proof sent to destination gateway
}
